# Carmel Connect deployment controller

This public repository contains only the guarded release controller for the private
`Samantha1294/Carmel-connect` source repository. It contains no Carmel Connect source,
Google credential, Apps Script identifier, student data, workbook data, or runtime log.

GitHub Free enforces branch protection, CODEOWNERS, environment deployment restrictions,
and environment secrets for this public repository. The
private source repository remains private and is read through a fine-grained token limited
to read-only Contents access on that one repository.

## Security model

* Deployment jobs exist only on protected `main` and run only when the repository owner
  applies an existing target-specific label to an issue authored by that owner. Pull
  requests run credential-free controller tests only.
* The issue body is one strict JSON request containing full source and expected-current
  commit SHAs. Branch names are rejected.
* The controller fetches Git blobs from the private repository, verifies blob integrity,
  requires the exact 14-file Apps Script inventory, and writes only those files locally.
* Candidate tests run in a separate GitHub-hosted job from every credential-bearing
  execution step. Their detailed output is suppressed because this controller is public.
* Both targets dispatch a strict, exact-SHA payload to a private executor repository whose trusted
  workflow runs on a dedicated self-hosted Mac runner. Candidate source is handled only as
  data and is never executed on that Mac.
* The Mac uses its existing local clasp authentication and locally stored, hash-allowlisted
  DEV and production project configurations. The existing staff deployment ID is also
  locally hash-allowlisted. No Google OAuth or clasp credential is stored in GitHub.
* Every run is serialized. The Apps Script API endpoint/method allowlist contains no
  trigger, Script Properties, Sheets, Drive, Gmail, Blackbaud, permissions, scripts.run,
  deployment-create, or deployment-delete operation.
* Manifest changes and any request marked high-risk are blocked. Those require a separate
  explicitly approved procedure.
* Production requires a successful DEV workflow run for the same exact source SHA and a
  separate owner-applied production label. It updates only the allowlisted existing staff
  deployment after creating and verifying an immutable version.

## One-time owner setup

1. Create this repository as **public**, with no generated README/license/gitignore.
2. Publish this reviewed controller to `main`, then protect `main` with an active public-
   repository ruleset: require a pull request, block force pushes and deletion, and do not
   allow bypass. For a single-owner repository, require zero independent approvals so the
   owner can merge only after the credential-free controller check succeeds.
3. Create existing labels `deploy-dev-approved` and `deploy-production-approved`. Do not
   permit Actions to create arbitrary approval labels.
4. Create `carmel-dev`, choose selected branches and tags, and allow exactly branch `main`
   with no tags. Add environment secrets `CARMEL_SOURCE_TOKEN` and
   `CARMEL_EXECUTOR_TOKEN`. The former is read-only source access; the latter is limited to
   dispatching and reading Actions in the private executor repository.
5. The source token is a fine-grained PAT owned by the school-controlled GitHub account,
   limited to only `Samantha1294/Carmel-connect`, with **Contents: Read-only** and no other
   repository or account permissions. Set an expiry and rotate it.
6. Register a dedicated self-hosted macOS runner only with the private
   `Samantha1294/Carmel-connect-runner` repository and add the custom label
   `Carmel-Connect-DEV-Mac`. The workflow also requires the built-in `macOS` and `ARM64`
   labels. Run it as a dedicated local service account when practical.
7. On that Mac, set `CARMEL_SOURCE_REPO_PATH` to the authenticated local working copy of the
   private authoritative source and `CARMEL_DEV_CLASP_PROJECT` to a durable local
   `.clasp.json` that targets only DEV. These values and clasp authentication stay local.
8. After the DEV bridge test passes, create `carmel-production`, restrict it to `main`, and
   add the same narrowly scoped source and executor tokens as environment secrets. Production
   identifiers remain only in local runner files; they are never GitHub secrets or repository
   content.

## Release request

Create an issue whose entire body is JSON, then apply the DEV label:

```json
{"schema":1,"target":"dev","source_sha":"FULL_SHA","expected_head_sha":"FULL_CURRENT_DEV_HEAD_SHA","expected_version":null,"dev_run_id":null,"request_id":"unique-id","risk":"standard"}
```

The controller intentionally does not close issues or post comments. The run summary reports
transport verification. Authenticated UI/runtime smoke testing remains a separate acceptance
step and does not require a Terminal.

After that exact DEV run succeeds and is approved, create a separate issue and apply only the
production label:

```json
{"schema":1,"target":"production","source_sha":"FULL_TESTED_SHA","expected_head_sha":"FULL_CURRENT_PRODUCTION_HEAD_SHA","expected_version":165,"dev_run_id":SUCCESSFUL_DEV_CONTROLLER_RUN_ID,"request_id":"unique-production-id","risk":"standard"}
```
