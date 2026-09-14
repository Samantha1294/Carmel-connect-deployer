import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import controller as c

SOURCE = {name: "source:" + name for name in c.FILES}
SOURCE["appsscript.json"] = '{"runtimeVersion":"V8"}\n'
BASELINE = dict(SOURCE, **{"Scripts.html": "previous client\n"})

REQUEST = {"schema": 1, "target": "dev", "source_sha": "a" * 40,
           "expected_head_sha": "a" * 40, "expected_version": None,
           "dev_run_id": None, "request_id": "dev-test", "risk": "standard"}


class FakeAPI:
    def __init__(self, target="dev", source=None):
        self.target, self.script_id = target, "script"
        self.staff_id = "staff" if target == "production" else None
        self.head = copy.deepcopy(source or BASELINE)
        self.versions = {165: copy.deepcopy(BASELINE)}
        self.records = {
            "staff": {"deploymentConfig": {"scriptId": "script", "versionNumber": 165,
                      "manifestFileName": "appsscript", "description": "existing"},
                      "entryPoints": [{"webApp": {"url": "unchanged"}}]},
            "other": {"deploymentConfig": {"versionNumber": 114}, "entryPoints": []}}
        self.writes, self.fail_readback, self.fail_immutable = [], False, False
        self.unrelated_change, self.entrypoint_change, self.delay = False, False, 0
        self.old_records = None

    def call(self, method, suffix="", body=None):
        if method == "GET" and suffix == "":
            return {"scriptId": self.script_id, "parentId": "bound-workbook"}
        self.writes.append((method, suffix, copy.deepcopy(body)))
        if suffix == "/content": self.head = c.api_source(body)
        elif suffix == "/versions": self.versions[166] = copy.deepcopy(self.head); return {"versionNumber": 166}
        elif suffix == "/deployments/staff":
            self.old_records = copy.deepcopy(self.records)
            self.records["staff"]["deploymentConfig"] = copy.deepcopy(body["deploymentConfig"])
            if self.unrelated_change: self.records["other"]["deploymentConfig"]["versionNumber"] = 115
            if self.entrypoint_change: self.records["staff"]["entryPoints"] = []
        else: raise AssertionError((method, suffix))
        return {}

    def deployments(self):
        if self.old_records is not None and self.delay:
            self.delay -= 1; return copy.deepcopy(self.old_records)
        return copy.deepcopy(self.records)

    def content(self, version=None):
        result = copy.deepcopy(self.head if version is None else self.versions[version])
        if (self.fail_readback and self.writes and version is None) or (self.fail_immutable and version == 166):
            result["Code.js"] += "DRIFT"
        return result


class FakeExecutor:
    def __init__(self, existing=False, wrong_main=False):
        self.dispatched = False
        self.posts = []
        self.existing = existing
        self.wrong_main = wrong_main

    def get(self, path):
        if path == "/git/ref/heads/main":
            return {"object": {"sha": ("f" * 40 if self.wrong_main else c.EXECUTOR_SHA)}}
        if path.startswith("/actions/workflows/"):
            runs = []
            if self.existing or self.dispatched:
                runs = [{"id": 456, "display_title": "Carmel release dev-test / 123",
                         "event": "repository_dispatch", "head_sha": c.EXECUTOR_SHA,
                         "path": ".github/workflows/execute-dev.yml",
                         "actor": {"login": c.OWNER}, "status": "completed",
                         "conclusion": "success", "run_attempt": 1}]
            return {"total_count": len(runs), "workflow_runs": runs}
        if path == "/actions/runs/456/attempts/1/jobs?per_page=100":
            return {"total_count": 1, "jobs": [{
                "name": "Deploy exact commit", "conclusion": "success",
                "steps": [{"name": "Verified release " + REQUEST["source_sha"],
                           "conclusion": "success"}],
            }]}
        raise AssertionError(path)

    def post(self, path, body):
        self.posts.append((path, copy.deepcopy(body)))
        self.dispatched = True


class Tests(unittest.TestCase):
    def prod_request(self):
        return dict(REQUEST, target="production", expected_version=165, dev_run_id=123)

    def run_release(self, api, request=None, expected=None, baseline=None):
        return c.release(api, request or REQUEST, expected or SOURCE, baseline or BASELINE,
                         lambda message: None, wait=lambda seconds: None)

    def test_request_strict_and_high_risk_rejected(self):
        self.assertEqual(c.parse_request(json.dumps(REQUEST))["target"], "dev")
        for bad in [dict(REQUEST, source_sha="main"), dict(REQUEST, extra=True),
                    dict(REQUEST, target="other"), dict(REQUEST, risk="high")]:
            with self.subTest(bad=bad), self.assertRaises(c.Stop):
                c.parse_request(json.dumps(bad))

    def test_production_request_accepts_optional_dev_evidence(self):
        with_evidence = self.prod_request()
        without_evidence = dict(with_evidence, dev_run_id=None)
        self.assertEqual(
            c.parse_request(json.dumps(with_evidence))["dev_run_id"], 123)
        self.assertIsNone(
            c.parse_request(json.dumps(without_evidence))["dev_run_id"])
        for invalid in (0, "123"):
            with self.subTest(invalid_dev_run_id=invalid), self.assertRaises(c.Stop):
                c.parse_request(json.dumps(
                    dict(with_evidence, dev_run_id=invalid)))

    def test_dev_evidence_verification_runs_only_when_supplied(self):
        controller = object()
        with patch.object(c, "verify_dev_evidence") as verify:
            c.verify_optional_dev_evidence(
                controller, dict(self.prod_request(), dev_run_id=None))
            verify.assert_not_called()
            c.verify_optional_dev_evidence(controller, self.prod_request())
            verify.assert_called_once_with(
                controller, 123, self.prod_request()["source_sha"])
            c.verify_optional_dev_evidence(controller, REQUEST)
            verify.assert_called_once()

    def test_secret_identifiers_use_hash_allowlist(self):
        value = "known"
        with patch.object(c, "mask"):
            self.assertEqual(c.secret_identifier(value, c.hashlib.sha256(value.encode()).hexdigest(), "x"), value)
            with self.assertRaises(c.Stop): c.secret_identifier("wrong", "0" * 64, "x")

    def test_source_round_trip_exact(self):
        source = dict(SOURCE, **{"Code.js": "// café\r\nconst x = '字';\n\n"})
        self.assertEqual(c.api_source({"files": c.api_files(source)}), source)

    def test_github_blob_accepts_api_line_wrapping_but_rejects_invalid_base64(self):
        raw = b"verified source bytes"
        encoded = c.base64.b64encode(raw).decode()
        tree = {"Code.js": {"type": "blob", "mode": "100644",
                            "sha": c.blob_hash(raw)}}
        github = c.GitHub("token", c.SOURCE_REPO)
        with patch.object(github, "get", return_value={
                "encoding": "base64", "content": encoded[:8] + "\n" + encoded[8:]}):
            self.assertEqual(github.file("a" * 40, "Code.js", tree), raw)
        with patch.object(github, "get", return_value={
                "encoding": "base64", "content": encoded + "!"}):
            with self.assertRaises(Exception):
                github.file("a" * 40, "Code.js", tree)

    def test_dev_push_only_and_readback(self):
        api = FakeAPI()
        report = self.run_release(api)
        self.assertEqual([(m, p) for m, p, b in api.writes], [("PUT", "/content")])
        self.assertEqual(report["files_verified"], 14)

    def test_drift_and_manifest_change_block_all_writes(self):
        for baseline, expected in [(dict(BASELINE, **{"Code.js": "drift"}), SOURCE),
                                   (BASELINE, dict(SOURCE, **{"appsscript.json": "changed"}))]:
            api = FakeAPI(source=baseline)
            with self.assertRaises(c.Stop): self.run_release(api, expected=expected)
            self.assertEqual(api.writes, [])

    def test_readback_failure_stops_before_version(self):
        api = FakeAPI("production"); api.fail_readback = True
        with self.assertRaises(c.Stop): self.run_release(api, self.prod_request())
        self.assertEqual(len(api.writes), 1)

    def test_production_updates_only_staff(self):
        api = FakeAPI("production"); before = copy.deepcopy(api.records)
        report = self.run_release(api, self.prod_request())
        self.assertEqual([(m, p) for m, p, b in api.writes],
                         [("PUT", "/content"), ("POST", "/versions"),
                          ("PUT", "/deployments/staff")])
        self.assertEqual(report["version"], 166)
        self.assertEqual(api.records["other"], before["other"])
        self.assertEqual(api.records["staff"]["entryPoints"], before["staff"]["entryPoints"])

    def test_wrong_staff_baseline_blocks_write(self):
        api = FakeAPI("production"); api.records["staff"]["deploymentConfig"]["versionNumber"] = 164
        with self.assertRaises(c.Stop): self.run_release(api, self.prod_request())
        self.assertEqual(api.writes, [])

    def test_immutable_failure_blocks_deployment_update(self):
        api = FakeAPI("production"); api.fail_immutable = True
        with self.assertRaises(c.Stop): self.run_release(api, self.prod_request())
        self.assertEqual(len(api.writes), 2)

    def test_unrelated_or_entrypoint_change_detected(self):
        for attr in ("unrelated_change", "entrypoint_change"):
            api = FakeAPI("production"); setattr(api, attr, True)
            with self.subTest(attr=attr), self.assertRaises(c.Stop): self.run_release(api, self.prod_request())

    def test_endpoint_allowlist(self):
        api = c.AppsScript.__new__(c.AppsScript)
        api.target, api.script_id, api.staff_id, api.token = "dev", "script", None, "token"
        with patch.object(c, "http_json") as network:
            for method, suffix in [("POST", "/versions"), ("POST", "/deployments"),
                                   ("DELETE", "/deployments/x"), ("POST", ":run"),
                                   ("PUT", "/properties"), ("POST", "/triggers")]:
                with self.subTest(suffix=suffix), self.assertRaises(c.Stop): api.call(method, suffix)
            network.assert_not_called()

    def test_executor_dispatch_is_exact_sha_and_attested(self):
        executor = FakeExecutor()
        env = {"GITHUB_SHA": "c" * 40, "GITHUB_RUN_ID": "123",
               "GITHUB_EVENT_ISSUE_NUMBER": "7"}
        report = c.dispatch_executor(executor, REQUEST, env, wait=lambda seconds: None)
        self.assertEqual(report["executor_run_id"], 456)
        self.assertEqual(len(executor.posts), 1)
        path, body = executor.posts[0]
        self.assertEqual(path, "/dispatches")
        self.assertEqual(body["event_type"], c.EXECUTOR_EVENT)
        self.assertEqual(body["client_payload"]["source_sha"], REQUEST["source_sha"])
        self.assertEqual(body["client_payload"]["expected_head_sha"],
                         REQUEST["expected_head_sha"])
        self.assertIsNone(body["client_payload"]["expected_version"])
        self.assertIsNone(body["client_payload"]["dev_run_id"])
        self.assertEqual(body["client_payload"]["executor_sha"], c.EXECUTOR_SHA)
        self.assertEqual(len(body["client_payload"]), 10)

    def test_direct_production_dispatch_preserves_null_dev_evidence(self):
        executor = FakeExecutor()
        request = dict(self.prod_request(), dev_run_id=None)
        env = {"GITHUB_SHA": "c" * 40, "GITHUB_RUN_ID": "123",
               "GITHUB_EVENT_ISSUE_NUMBER": "7"}
        c.dispatch_executor(executor, request, env, wait=lambda seconds: None)
        payload = executor.posts[0][1]["client_payload"]
        self.assertEqual(payload["target"], "production")
        self.assertIsNone(payload["dev_run_id"])
        self.assertEqual(payload["source_sha"], request["source_sha"])

    def test_executor_dispatch_rejects_changed_or_duplicate_executor(self):
        env = {"GITHUB_SHA": "c" * 40, "GITHUB_RUN_ID": "123",
               "GITHUB_EVENT_ISSUE_NUMBER": "7"}
        for executor in (FakeExecutor(wrong_main=True), FakeExecutor(existing=True)):
            with self.subTest(executor=executor), self.assertRaises(c.Stop):
                c.dispatch_executor(executor, REQUEST, env, wait=lambda seconds: None)
            self.assertEqual(executor.posts, [])

    def test_workflow_events_are_safely_separated(self):
        workflow = (c.ROOT.parent / c.WORKFLOW).read_text()
        self.assertIn("issues:", workflow)
        self.assertIn("pull_request:", workflow)
        self.assertNotIn("workflow_dispatch", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("github.event_name == 'pull_request'", workflow)
        self.assertIn("github.event_name == 'issues'", workflow)
        self.assertIn("name: Verify deployment controller", workflow)
        self.assertNotIn("GOOGLE_OAUTH_JSON:", workflow)
        self.assertEqual(workflow.count("secrets.CARMEL_EXECUTOR_TOKEN"), 2)
        self.assertEqual(workflow.count("run: python3 -I .bridge/controller.py dispatch"), 2)
        self.assertNotIn("controller.py deploy dev", workflow)
        self.assertIn("name: Test exact DEV candidate", workflow)
        self.assertIn("needs: [validate, candidate-test-dev]", workflow)
        self.assertIn("environment: carmel-dev", workflow)
        self.assertIn("environment: carmel-production", workflow)
        self.assertIn("output suppressed in this public controller", workflow)

    def test_no_plaintext_target_identifiers(self):
        controller = (c.ROOT / "controller.py").read_text()
        for prefix in ("1IMR_", "173oq", "AKfycbyp"):
            self.assertNotIn(prefix, controller)


if __name__ == "__main__": unittest.main()
