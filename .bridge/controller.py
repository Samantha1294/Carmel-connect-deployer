"""Public, credential-isolated Carmel Connect release controller.

This file never imports candidate code and exposes no Apps Script identifiers.
"""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

CONTROLLER_REPO = "Samantha1294/Carmel-connect-deployer"
SOURCE_REPO = "Samantha1294/Carmel-connect"
EXECUTOR_REPO = "Samantha1294/Carmel-connect-runner"
OWNER = "Samantha1294"
BRANCH = "main"
WORKFLOW = ".github/workflows/carmel-release.yml"
EXECUTOR_WORKFLOW = "execute-dev.yml"
EXECUTOR_EVENT = "carmel-release-approved-v1"
EXECUTOR_SHA = "c0a99d818e48a3b28303afb3a19eb85d9631cc87"
LABELS = {"dev": "deploy-dev-approved", "production": "deploy-production-approved"}

# SHA-256 allowlists let the public controller validate identifiers supplied only
# through protected environment secrets without publishing the identifiers.
TARGET_HASHES = {
    "dev": "d335ead5c8a7172f81a719fb179190ef6aba0ffdb4dc64b39c8f65e386ed381f",
    "production": "1136ee0599cfddf0069f2ba358d879c7b22db200209483bba9bb316699aae25f",
}
STAFF_HASH = "e1365f9ba8eec709b83c468a64dfbf43966871138fd011bbb59b5d902047b2cf"

FILES = (
    "appsscript.json", "AcademicPolicy.js", "BlackbaudApi.js", "BlackbaudFamilySync.js",
    "BlackbaudFamilySyncRepair.js", "BlackbaudGradeSync.js",
    "BlackbaudMedicalDiagnostic.js", "BehaviorRisk.js", "Code.js", "ConductSync.js",
    "Index.html", "Scripts.html", "Styles.html", "StudentCollegePlans.js",
    "TeacherGradeAudit.js", "WatchListFilters.js",
)
TEST_FILES = (
    "tests/academic-policy.cjs", "tests/academic-profile-integration.cjs",
    "tests/academic-standing-ui.cjs", "tests/security-authorization.cjs",
    "tests/security-hardening.cjs", "tests/student-college-plans.cjs",
)
ROOT = Path(__file__).resolve().parent


class Stop(RuntimeError):
    pass


def check(condition, message):
    if not condition:
        raise Stop(message)


def full_sha(value):
    check(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value),
          "Expected a full lowercase 40-character commit SHA")
    return value


def secret_identifier(value, expected_hash, label):
    check(isinstance(value, str) and value, f"Missing {label} environment secret")
    mask(value)
    check(hashlib.sha256(value.encode()).hexdigest() == expected_hash,
          f"{label} is not allowlisted")
    return value


def blob_hash(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_json(url, method="GET", body=None, token=None, form=False, allow_empty=False):
    host = urllib.parse.urlsplit(url).hostname
    check(host in {"api.github.com", "oauth2.googleapis.com", "script.googleapis.com"},
          "Network destination not allowlisted")
    headers = {"Accept": "application/json", "User-Agent": "Carmel-Connect-Release"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        headers["Content-Type"] = ("application/x-www-form-urlencoded" if form
                                   else "application/json")
        data = (urllib.parse.urlencode(body).encode() if form else
                json.dumps(body, ensure_ascii=False).encode())
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=90) as response:
            payload = response.read(30_000_001)
            check(len(payload) <= 30_000_000, "Response exceeded size limit")
            if allow_empty and not payload:
                return None
            return json.loads(payload)
    except urllib.error.HTTPError as error:
        raise Stop(f"HTTP {error.code} from {host}; response withheld; "
                   "no write retry attempted") from None
    except (urllib.error.URLError, TimeoutError):
        raise Stop("Network failure; remote write outcome may be unknown; inspect before retry") from None


class GitHub:
    def __init__(self, token, repo):
        check(bool(token), "Missing GitHub token")
        check(repo in {CONTROLLER_REPO, SOURCE_REPO, EXECUTOR_REPO},
              "GitHub repository not allowlisted")
        self.token, self.repo = token, repo

    def get(self, path):
        check(path.startswith("/") and ".." not in path, "Invalid GitHub path")
        return http_json("https://api.github.com/repos/" + self.repo + path, token=self.token)

    def post(self, path, body):
        check(path.startswith("/") and ".." not in path, "Invalid GitHub path")
        return http_json("https://api.github.com/repos/" + self.repo + path,
                         "POST", body, self.token, allow_empty=True)

    def tree(self, commit):
        tree = self.get(f"/git/trees/{full_sha(commit)}?recursive=1")
        check(tree.get("truncated") is False, "Truncated Git tree")
        return {entry["path"]: entry for entry in tree["tree"]}

    def file(self, commit, name, tree=None):
        tree = tree if tree is not None else self.tree(commit)
        entry = tree.get(name, {})
        check(entry.get("type") == "blob" and entry.get("mode") == "100644",
              "Missing or non-regular source file")
        result = self.get(f"/git/blobs/{full_sha(entry['sha'])}")
        check(result.get("encoding") == "base64", "Unexpected Git blob encoding")
        encoded = re.sub(r"\s+", "", result["content"])
        raw = base64.b64decode(encoded, validate=True)
        check(blob_hash(raw) == entry["sha"], "Git blob integrity failure")
        return raw

    def source(self, commit):
        tree = self.tree(commit)
        names = {name for name in tree if "/" not in name and
                 (name == "appsscript.json" or Path(name).suffix.lower() in
                  {".js", ".gs", ".html"})}
        check(names == set(FILES), "Apps Script source inventory mismatch")
        result = {}
        for name in FILES:
            result[name] = self.file(commit, name, tree).decode("utf-8")
        return result, tree


def parse_request(body):
    try:
        request = json.loads(body)
    except (TypeError, ValueError):
        raise Stop("Issue body must be a single JSON object") from None
    fields = {"schema", "target", "source_sha", "expected_head_sha",
              "expected_version", "dev_run_id", "request_id", "risk"}
    check(isinstance(request, dict) and set(request) == fields,
          "Unexpected release request fields")
    check(request["schema"] == 1, "Unsupported request schema")
    target = request["target"]
    check(target in LABELS, "Target not allowlisted")
    full_sha(request["source_sha"])
    full_sha(request["expected_head_sha"])
    check(re.fullmatch(r"[A-Za-z0-9_-]{1,80}", request["request_id"] or ""),
          "Invalid request ID")
    check(request["risk"] == "standard",
          "High-risk releases require a separate explicitly approved procedure")
    if target == "dev":
        check(request["expected_version"] is None and request["dev_run_id"] is None,
              "DEV request contains production-only inputs")
    else:
        check(type(request["expected_version"]) is int and request["expected_version"] > 0,
              "Production baseline version required")
        check(request["dev_run_id"] is None or
              (type(request["dev_run_id"]) is int and request["dev_run_id"] > 0),
              "DEV evidence must be a positive run ID when supplied")
    return request


def event_request(env):
    check(env.get("GITHUB_REPOSITORY") == CONTROLLER_REPO, "Wrong controller repository")
    check(env.get("GITHUB_REF") == "refs/heads/main", "Workflow is not running from main")
    check(env.get("GITHUB_EVENT_NAME") == "issues", "Only labeled-issue events are trusted")
    check(env.get("GITHUB_WORKFLOW_REF") ==
          f"{CONTROLLER_REPO}/{WORKFLOW}@refs/heads/main", "Untrusted workflow ref")
    check(env.get("GITHUB_WORKFLOW_SHA") == full_sha(env.get("GITHUB_SHA", "")),
          "Controller SHA mismatch")
    event_path = Path(env.get("GITHUB_EVENT_PATH", ""))
    check(event_path.is_file(), "Missing GitHub event payload")
    event = json.loads(event_path.read_text())
    check(event.get("action") == "labeled", "Unexpected issue action")
    check(event.get("sender", {}).get("login") == OWNER and
          event.get("issue", {}).get("user", {}).get("login") == OWNER,
          "Release request and approval must come from the repository owner")
    check(event.get("issue", {}).get("state") == "open", "Release request issue is not open")
    request = parse_request(event.get("issue", {}).get("body"))
    check(event.get("label", {}).get("name") == LABELS[request["target"]],
          "Approval label does not match target")
    return request


def write_candidate(github, request, destination):
    check(not destination.exists(), "Candidate destination already exists")
    source, tree = github.source(request["source_sha"])
    destination.mkdir(mode=0o700)
    for name, content in source.items():
        path = destination / name
        path.write_text(content, encoding="utf-8", newline="")
    for name in TEST_FILES:
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(github.file(request["source_sha"], name, tree))
    manifest = {name: blob_hash(source[name].encode("utf-8")) for name in FILES}
    (destination / ".verified-source.json").write_text(json.dumps({
        "source_sha": request["source_sha"], "files": manifest
    }, sort_keys=True) + "\n")


def read_candidate(request, destination):
    check(destination.is_dir() and not destination.is_symlink(), "Candidate directory missing")
    manifest_path = destination / ".verified-source.json"
    check(manifest_path.is_file() and not manifest_path.is_symlink(), "Source manifest missing")
    manifest = json.loads(manifest_path.read_text())
    check(manifest.get("source_sha") == request["source_sha"] and
          set(manifest.get("files", {})) == set(FILES), "Source manifest mismatch")
    source = {}
    for name in FILES:
        path = destination / name
        check(path.is_file() and not path.is_symlink(), "Candidate source missing or unsafe")
        raw = path.read_bytes()
        check(blob_hash(raw) == manifest["files"][name], "Candidate source changed after fetch")
        source[name] = raw.decode("utf-8")
    return source


def api_source(content):
    result = {}
    extensions = {"SERVER_JS": ".js", "HTML": ".html", "JSON": ".json"}
    for item in content.get("files", []):
        check(item.get("type") in extensions and isinstance(item.get("source"), str),
              "Unexpected Apps Script file type/content")
        name = item["name"] + extensions[item["type"]]
        check(name not in result, "Duplicate Apps Script file")
        result[name] = item["source"]
    return result


def api_files(source):
    extensions = {".js": "SERVER_JS", ".html": "HTML", ".json": "JSON"}
    return [{"name": Path(name).stem, "type": extensions[Path(name).suffix],
             "source": source[name]} for name in FILES]


def same_source(actual, expected, label):
    check(actual == expected, label + " source mismatch; no further write permitted")


class AppsScript:
    def __init__(self, target, script_id, staff_id, secret):
        check(target in TARGET_HASHES, "Unknown target")
        self.script_id = secret_identifier(script_id, TARGET_HASHES[target], "Script ID")
        self.staff_id = (secret_identifier(staff_id, STAFF_HASH, "staff deployment ID")
                         if target == "production" else None)
        self.target = target
        try:
            credential = json.loads(secret)
            check(set(credential) == {"client_id", "client_secret", "refresh_token"},
                  "Expected dedicated OAuth credential fields")
            check(all(isinstance(v, str) and v for v in credential.values()),
                  "Incomplete OAuth credential")
        except (ValueError, TypeError):
            raise Stop("Malformed OAuth secret; value withheld") from None
        for value in credential.values():
            mask(value)
        token = http_json("https://oauth2.googleapis.com/token", "POST",
                          dict(credential, grant_type="refresh_token"), form=True)
        self.token = token.get("access_token")
        check(isinstance(self.token, str) and self.token, "OAuth exchange returned no token")
        mask(self.token)

    def call(self, method, suffix="", body=None):
        allowed = method == "GET" and (suffix == "" or suffix == "/content" or
            re.fullmatch(r"/content\?versionNumber=[1-9][0-9]*", suffix) or
            suffix == "/deployments" or
            re.fullmatch(r"/deployments\?pageToken=[A-Za-z0-9%_.~-]+", suffix))
        allowed = allowed or (method == "PUT" and suffix == "/content")
        if self.target == "production":
            allowed = allowed or (method == "POST" and suffix == "/versions")
            allowed = allowed or (method == "PUT" and suffix == "/deployments/" + self.staff_id)
        check(allowed, "Apps Script operation not allowlisted")
        return http_json("https://script.googleapis.com/v1/projects/" + self.script_id + suffix,
                         method, body, self.token)

    def content(self, version=None):
        suffix = "/content" + (f"?versionNumber={version}" if version is not None else "")
        return api_source(self.call("GET", suffix))

    def deployments(self):
        records, suffix, tokens = {}, "/deployments", set()
        while True:
            result = self.call("GET", suffix)
            for record in result.get("deployments", []):
                key = record["deploymentId"]
                check(key not in records, "Duplicate deployment ID")
                records[key] = {"deploymentConfig": record["deploymentConfig"],
                                "entryPoints": record.get("entryPoints", [])}
            token = result.get("nextPageToken")
            if not token:
                return records
            check(token not in tokens and len(tokens) < 100, "Invalid deployment pagination")
            tokens.add(token)
            suffix = "/deployments?pageToken=" + urllib.parse.quote(token, safe="")


def mask(value):
    value = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print("::add-mask::" + value, flush=True)


def verify_dev_evidence(controller, run_id, source_sha):
    run = controller.get(f"/actions/runs/{run_id}")
    check(run.get("status") == "completed" and run.get("conclusion") == "success",
          "DEV evidence run did not succeed")
    check(run.get("event") == "issues" and run.get("path") == WORKFLOW and
          run.get("repository", {}).get("full_name") == CONTROLLER_REPO,
          "DEV evidence came from an untrusted workflow")
    attempt = int(run["run_attempt"])
    jobs = controller.get(f"/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    check(jobs.get("total_count", 0) <= 100, "Truncated evidence jobs")
    dev_jobs = [job for job in jobs["jobs"] if job["name"] == "Deploy DEV"]
    check(len(dev_jobs) == 1 and dev_jobs[0]["conclusion"] == "success",
          "DEV deployment job did not complete")
    step_name = "Verified DEV release " + source_sha
    steps = [step for step in dev_jobs[0]["steps"] if step["name"] == step_name]
    check(len(steps) == 1 and steps[0]["conclusion"] == "success",
          "DEV run does not attest this exact source SHA")


def verify_optional_dev_evidence(controller, request):
    if request["target"] == "production" and request["dev_run_id"] is not None:
        verify_dev_evidence(controller, request["dev_run_id"], request["source_sha"])


def executor_runs(executor, display_title):
    result = executor.get(
        f"/actions/workflows/{EXECUTOR_WORKFLOW}/runs?event=repository_dispatch&per_page=50")
    runs = result.get("workflow_runs", [])
    check(isinstance(runs, list) and len(runs) <= 50, "Invalid executor run lookup")
    return [run for run in runs
            if run.get("display_title") == display_title]


def verify_executor_run(executor, run, request):
    check(run.get("event") == "repository_dispatch" and
          run.get("head_sha") == EXECUTOR_SHA and
          run.get("path") == ".github/workflows/execute-dev.yml" and
          run.get("actor", {}).get("login") == OWNER,
          "Release executor run identity mismatch")
    check(run.get("status") == "completed" and run.get("conclusion") == "success",
          "Release executor run did not succeed")
    attempt = int(run["run_attempt"])
    jobs = executor.get(f"/actions/runs/{run['id']}/attempts/{attempt}/jobs?per_page=100")
    check(jobs.get("total_count", 0) <= 100, "Truncated executor jobs")
    selected = [job for job in jobs.get("jobs", []) if job.get("name") == "Deploy exact commit"]
    check(len(selected) == 1 and selected[0].get("conclusion") == "success",
          "Release executor deployment job did not complete")
    step_name = "Verified release " + request["source_sha"]
    steps = [step for step in selected[0].get("steps", []) if step.get("name") == step_name]
    check(len(steps) == 1 and steps[0].get("conclusion") == "success",
          "Release executor does not attest this exact source SHA")


def dispatch_executor(executor, request, env, wait=time.sleep):
    check(request["target"] in {"dev", "production"}, "Unsupported executor target")
    controller_sha = full_sha(env.get("GITHUB_SHA", ""))
    current = executor.get("/git/ref/heads/main")
    check(current.get("object", {}).get("sha") == EXECUTOR_SHA,
          "Private executor main does not match the controller allowlist")
    run_id = int(env.get("GITHUB_RUN_ID", "0"))
    issue_number = int(env.get("GITHUB_EVENT_ISSUE_NUMBER", "0"))
    check(run_id > 0 and issue_number > 0,
          "Missing trusted controller run metadata")
    title = f"Carmel release {request['request_id']} / {run_id}"
    check(not executor_runs(executor, title), "Duplicate release executor request identity")
    payload = {
        "target": request["target"],
        "source_sha": request["source_sha"],
        "expected_head_sha": request["expected_head_sha"],
        "expected_version": request["expected_version"],
        "dev_run_id": request["dev_run_id"],
        "request_id": request["request_id"],
        "risk": request["risk"],
        "controller_sha": controller_sha,
        "controller_run_id": run_id,
        "executor_sha": EXECUTOR_SHA,
    }
    executor.post("/dispatches", {"event_type": EXECUTOR_EVENT, "client_payload": payload})
    for unused_attempt in range(181):
        matches = executor_runs(executor, title)
        check(len(matches) <= 1, "Duplicate release executor runs detected")
        if matches:
            run = matches[0]
            if run.get("status") == "completed":
                verify_executor_run(executor, run, request)
                return {"executor_run_id": run["id"], "executor_sha": EXECUTOR_SHA}
        wait(10)
    raise Stop("Timed out waiting for the release executor; no retry attempted")


def release(api, request, expected, baseline, progress, wait=time.sleep):
    project = api.call("GET")
    check(project.get("scriptId") == api.script_id and bool(project.get("parentId")),
          "Target metadata mismatch or project is not container-bound")
    before = api.deployments()
    production = request["target"] == "production"
    if production:
        check(api.staff_id in before, "Existing staff deployment missing")
        config = before[api.staff_id]["deploymentConfig"]
        check(config.get("scriptId") == api.script_id and
              config.get("versionNumber") == request["expected_version"] and
              config.get("manifestFileName") == "appsscript",
              "Staff deployment baseline mismatch")
        same_source(api.content(request["expected_version"]), baseline, "Deployed baseline")
    same_source(api.content(), baseline, "Preflight HEAD drift check")
    check(expected["appsscript.json"] == baseline["appsscript.json"],
          "Manifest change requires a separately reviewed release procedure")
    check(api.deployments() == before, "Deployment inventory changed during preflight")
    same_source(api.content(), baseline, "Immediate pre-write HEAD drift check")
    progress("Source push attempted")
    api.call("PUT", "/content", {"files": api_files(expected)})
    same_source(api.content(), expected, "Pushed HEAD")
    progress("Source pushed and verified")
    version = None
    if production:
        check(api.deployments() == before, "Deployment inventory drift before version creation")
        progress("Immutable version creation attempted")
        result = api.call("POST", "/versions", {
            "description": "Carmel Connect Git " + request["source_sha"]})
        version = result.get("versionNumber")
        check(type(version) is int and version > request["expected_version"],
              "Unexpected created version; inspect before retry")
        progress(f"Created version {version}; verifying")
        same_source(api.content(version), expected, "Immutable version")
        same_source(api.content(), expected, "HEAD before deployment update")
        check(api.deployments() == before, "Deployment inventory drift before update")
        wanted = copy.deepcopy(before)
        config = wanted[api.staff_id]["deploymentConfig"]
        config["versionNumber"] = version
        config["description"] = f"v{version} - Carmel Connect; Git {request['source_sha'][:7]}"
        progress(f"Staff deployment update to version {version} attempted")
        api.call("PUT", "/deployments/" + api.staff_id, {"deploymentConfig": config})
        for attempt in range(6):
            after = api.deployments()
            check(set(after) == set(before), "Deployment ID inventory changed")
            check(all(after[key] == before[key] for key in before if key != api.staff_id),
                  "Unrelated deployment changed")
            check(after[api.staff_id]["entryPoints"] == before[api.staff_id]["entryPoints"],
                  "Staff URL/access entry points changed")
            if after == wanted:
                break
            check(after[api.staff_id]["deploymentConfig"] == before[api.staff_id]["deploymentConfig"],
                  "Unexpected staff deployment configuration")
            if attempt == 5:
                raise Stop("Staff deployment update not visible after bounded verification")
            wait(2)
    else:
        check(api.deployments() == before, "DEV deployment configuration changed")
    progress("Release verified")
    return {"target": request["target"], "source_sha": request["source_sha"],
            "files_verified": len(expected), "version": version,
            "deployment_updated": bool(production),
            "runtime_smoke_test": "requires authenticated application review"}


def main():
    request = event_request(os.environ)
    command = sys.argv[1:]
    if command == ["validate"]:
        output = os.environ.get("GITHUB_OUTPUT")
        if output:
            with open(output, "a") as handle:
                handle.write(f"target={request['target']}\nsource_sha={request['source_sha']}\n")
        print(f"Validated owner-approved {request['target']} request for {request['source_sha']}")
        return
    if command == ["fetch"]:
        source = GitHub(os.environ.pop("SOURCE_TOKEN", ""), SOURCE_REPO)
        write_candidate(source, request, Path("candidate"))
        print(f"Verified and prepared exact source {request['source_sha']} ({len(FILES)} files)")
        return
    controller = GitHub(os.environ.get("GH_TOKEN"), CONTROLLER_REPO)
    current = controller.get("/git/ref/heads/main")
    check(current.get("object", {}).get("sha") == os.environ.get("GITHUB_SHA"),
          "Controller main advanced; stale queued release rejected")
    candidate = read_candidate(request, Path("candidate"))
    if command == ["dispatch"]:
        verify_optional_dev_evidence(controller, request)
        executor = GitHub(os.environ.pop("EXECUTOR_TOKEN", ""), EXECUTOR_REPO)
        report = dispatch_executor(executor, request, os.environ)
        report.update({"target": request["target"], "source_sha": request["source_sha"],
                       "files_verified": len(candidate)})
        text = json.dumps(report, indent=2)
        print(text)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as handle:
                handle.write("## Verified Carmel Connect release\n```json\n" +
                             text + "\n```\n")
        return
    check(command == ["deploy", "production"] and request["target"] == "production",
          "Command and request target must match")
    source = GitHub(os.environ.pop("SOURCE_TOKEN", ""), SOURCE_REPO)
    baseline, unused = source.source(request["expected_head_sha"])
    verify_optional_dev_evidence(controller, request)
    api = AppsScript(request["target"], os.environ.pop("SCRIPT_ID", ""),
                     os.environ.pop("STAFF_DEPLOYMENT_ID", ""),
                     os.environ.pop("GOOGLE_OAUTH_JSON", ""))
    stage = ["Authenticated; no Apps Script write attempted"]
    def progress(message):
        stage[0] = message
        print(message, flush=True)
    try:
        report = release(api, request, candidate, baseline, progress)
    except Exception:
        print("Last confirmed/attempted stage: " + stage[0], flush=True)
        print("No automatic rollback or remote write retry was attempted.", flush=True)
        raise
    text = json.dumps(report, indent=2)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as handle:
            handle.write("## Verified Carmel Connect release\n```json\n" + text + "\n```\n")


if __name__ == "__main__":
    try:
        main()
    except Stop as error:
        print("STOP: " + str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("STOP: Unexpected controller error; details withheld. Inspect state before retry.",
              file=sys.stderr)
        sys.exit(1)
