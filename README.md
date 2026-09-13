# Carmel Connect deployment controller

This public repository contains only the guarded release controller for the private
`Samantha1294/Carmel-connect` source repository. It contains no Carmel Connect source,
Google credential, Apps Script identifier, student data, workbook data, or runtime log.

GitHub Free enforces branch protection, CODEOWNERS, environment deployment restrictions,
environment secrets, and required environment reviewers for this public repository. The
private source repository remains private and is read through a fine-grained token limited
to read-only Contents access on that one repository.

## Security model

* The workflow exists only on protected `main` and runs only when the repository owner
  applies an existing target-specific label to an issue authored by that owner.
* The issue body is one strict JSON request containing full source and expected-current
  commit SHAs. Branch names are rejected.
* The controller fetches Git blobs from the private repository, verifies blob integrity,
  requires the exact 14-file Apps Script inventory, and writes only those files locally.
* Candidate tests run without either the source token or Google credential in their step.
  Their detailed output is suppressed because this controller repository is public.
* DEV and production use separate GitHub environments and separate Google OAuth grants.
  IDs and credentials are environment secrets. Public code contains only their SHA-256
  allowlist values.
* Every run is serialized. The Apps Script API endpoint/method allowlist contains no
  trigger, Script Properties, Sheets, Drive, Gmail, Blackbaud, permissions, scripts.run,
  deployment-create, or deployment-delete operation.
* Manifest changes and any request marked high-risk are blocked. Those require a separate
  explicitly approved procedure.
* Production requires a successful DEV workflow run for the same exact source SHA and a
  protected production-environment approval. It updates only the allowlisted existing staff
  deployment after creating and verifying an immutable version.

## One-time owner setup

1. Create this repository as **public**, with no generated README/license/gitignore.
2. Publish this reviewed controller to `main`, then protect `main`: require a pull request,
   one approval, code-owner review, stale-review dismissal, conversation resolution, block
   force pushes and deletion, and do not allow bypass. On GitHub Free these controls are
   enforced for public repositories.
3. Create existing labels `deploy-dev-approved` and `deploy-production-approved`. Do not
   permit Actions to create arbitrary approval labels.
4. Create `carmel-dev`, restricted to protected branch `main`. Add environment secrets:
   `CARMEL_SOURCE_TOKEN`, `CARMEL_SCRIPT_ID`, and `CARMEL_GOOGLE_OAUTH_JSON`.
5. The source token is a fine-grained PAT owned by the school-controlled GitHub account,
   limited to only `Samantha1294/Carmel-connect`, with **Contents: Read-only** and no other
   repository or account permissions. Set an expiry and rotate it.
6. The DEV OAuth JSON has exactly `client_id`, `client_secret`, and `refresh_token`, from a
   dedicated school-controlled OAuth client/grant. Required scopes are Apps Script projects
   plus deployment read-only. It is not a clasp credential file.
7. Do not create or populate `carmel-production` until the DEV bridge test passes. Production
   later gets separate credentials, protected-branch restriction, and Samantha as required
   reviewer. The staff deployment ID exists only as `CARMEL_STAFF_DEPLOYMENT_ID` there.

## Release request

Create an issue whose entire body is JSON, then apply the DEV label:

```json
{"schema":1,"target":"dev","source_sha":"FULL_SHA","expected_head_sha":"FULL_CURRENT_DEV_HEAD_SHA","expected_version":null,"dev_run_id":null,"request_id":"unique-id","risk":"standard"}
```

The controller intentionally does not close issues or post comments. The run summary reports
transport verification. Authenticated UI/runtime smoke testing remains a separate acceptance
step and does not require a Terminal.
