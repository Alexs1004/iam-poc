# Test Strategy — Mini IAM Lab

This section documents how the automated test suites exercise the SCIM surface and supporting security controls.

## Goals
- Validate security behaviour (OAuth enforcement, scope checks, headers).
- Detect regressions in provisioning logic (create/disable/idempotence).
- Provide transparent metrics for recruiters (pytest counts, coverage target).

## Test layers
| Layer | What it covers | Command |
|-------|----------------|---------|
| Unit | SCIM handlers, provisioning helpers, audit signing, RBAC decorators | `make test` (runs `pytest -n auto -m "not integration"`) |
| Integration | Full SCIM + Keycloak stack (joiner/leaver flows, security headers) | `make test-e2e` |
| Security smoke | Critical OAuth/JWT/headers and secret-handling checks | `make test/security` |

Notes:
- `make test` runs in demo mode (`DEMO_MODE=true`) with mocked Keycloak responses; results (~240 tests) complete in ~2 s.
- `make test-all` chains the three targets above. Set `SKIP_E2E=true` to run only unit tests when needed.
- Coverage is ~90% (`pytest --cov=app`); the CI gate (see `.github/workflows/tests-coverage.yml`) fails below 80%.

## Key security test files
- `tests/test_scim_oauth_validation.py` — OAuth happy/negative paths (401/403/415).
- `tests/test_scim_api.py` — endpoint behaviour (PATCH active, DELETE soft-delete, PUT 501).
- `tests/test_scim_api_negatives.py` — malformed payloads, error schema assertions.
- `tests/test_api_decorators.py` — JWT validation (PyJWKClient) and scope enforcement.
- `tests/test_api_docs.py` — ReDoc/OpenAPI routes.

## Manual drills (optional)
- `make quickstart` → login at `https://localhost`, exercise JML UI.
- Issue a SCIM PATCH toggle (see docs/LOCAL_SCIM_TESTING.md) and confirm audit signature via `make verify-audit`.

## Reporting
- Coverage HTML: `pytest --cov=app --cov-report=html` → open `htmlcov/index.html`.
- Pytest timings log (xdist) helps identify slow tests for optimisation.
