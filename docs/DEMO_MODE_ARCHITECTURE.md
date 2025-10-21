# Demo Mode Architecture - Defense in Depth

## Configuration Constraint

**Rule:** `DEMO_MODE=true` **requires** `AZURE_USE_KEYVAULT=false`

Demo mode is designed for local development and uses hardcoded fallback secrets. It is incompatible with Azure Key Vault secret retrieval.

## Multi-Layer Protection Strategy

This project implements **defense in depth** to enforce the DEMO_MODE constraint at multiple levels:

### Layer 1: Proactive Validation (Recommended Path)
**File:** `scripts/validate_env.sh`  
**Trigger:** `make fresh-demo`, `make quickstart`, `make validate-env`

- Detects misconfiguration in `.env` file
- Automatically corrects `AZURE_USE_KEYVAULT=false` when `DEMO_MODE=true`
- Creates timestamped backup before modification
- **Advantage:** Fixes the problem at the source before Docker starts

**Usage:**
```bash
# Automatic validation
make fresh-demo        # Validates then resets and runs full demo
make quickstart        # Validates then runs stack + demo_jml.sh

# Manual validation
make validate-env      # Only validates/corrects .env
./scripts/validate_env.sh  # Direct script execution
```

### Layer 2: Runtime Guards (Safety Net)

Even with proactive validation, runtime guards remain **essential** because:
- Users may bypass `make` and use `docker-compose up` directly
- Users may edit `.env` manually after validation
- Scripts like `demo_jml.sh` can be run standalone
- Defense in depth principle: multiple safety layers

#### Python Runtime Guards
**Files:** `app/flask_app.py`, `app/provisioning_service.py`, `gunicorn.conf.py`

```python
DEMO_MODE = os.environ.get("DEMO_MODE", "false").lower() == "true"
if DEMO_MODE and os.environ.get("AZURE_USE_KEYVAULT", "false").lower() == "true":
    print("[...] WARNING: DEMO_MODE=true requires AZURE_USE_KEYVAULT=false (runtime guard)")
    print("[...] Forcing AZURE_USE_KEYVAULT=false | Run 'make validate-env' to fix .env permanently")
    os.environ["AZURE_USE_KEYVAULT"] = "false"
```

**Why duplicated across modules?**
- `flask_app.py`: Main application entry point
- `provisioning_service.py`: Can be loaded independently by SCIM API
- `gunicorn.conf.py`: Runs in worker processes, sees original Docker env vars

#### Bash Runtime Guard
**File:** `scripts/demo_jml.sh`

```bash
if [[ "${DEMO_MODE,,}" == "true" ]]; then
  if [[ "${AZURE_USE_KEYVAULT,,}" == "true" ]]; then
    echo "[demo] WARNING: DEMO_MODE=true requires AZURE_USE_KEYVAULT=false (runtime guard)"
    echo "[demo] Forcing AZURE_USE_KEYVAULT=false | Run 'make validate-env' to fix .env permanently"
    export AZURE_USE_KEYVAULT="false"
  fi
fi
```

## Workflow Scenarios

### Scenario A: Proper Workflow (Recommended)
1. User runs `make fresh-demo`
2. ✅ `validate_env.sh` detects and fixes `.env`
3. Docker starts with correct configuration
4. Runtime guards are silent (no misconfiguration detected)

### Scenario B: Direct Docker Usage
1. User runs `docker-compose up` directly
2. ❌ `validate_env.sh` is NOT executed
3. Docker loads misconfigured `.env` (DEMO_MODE=true, AZURE_USE_KEYVAULT=true)
4. ✅ Runtime guards detect and correct in-memory (logs warning)
5. Application runs safely with AZURE_USE_KEYVAULT=false

### Scenario C: Standalone Script
1. User runs `./scripts/demo_jml.sh` directly
2. ❌ `validate_env.sh` is NOT executed
3. ✅ Bash runtime guard corrects configuration
4. Script runs safely

## Log Messages Explained

### Proactive Validation Log (Layer 1)
```
⚠️  WARNING: DEMO_MODE=true is incompatible with AZURE_USE_KEYVAULT=true
   Auto-correcting: Setting AZURE_USE_KEYVAULT=false in .env
✅ Configuration corrected!
```
**Meaning:** `.env` file has been permanently fixed. Backup created.

### Runtime Guard Log (Layer 2)
```
[flask_app] WARNING: DEMO_MODE=true requires AZURE_USE_KEYVAULT=false (runtime guard)
[flask_app] Forcing AZURE_USE_KEYVAULT=false | Run 'make validate-env' to fix .env permanently
```
**Meaning:** Misconfiguration detected at runtime and corrected in-memory. Consider running `make validate-env` to fix the source.

## Best Practices

1. **Always use `make` targets** for standard workflows:
   - `make fresh-demo` for clean setup
   - `make quickstart` for stack startup
   
2. **Run `make validate-env`** after manually editing `.env`

3. **Don't remove runtime guards** - they're your safety net when working outside standard workflows

4. **Review logs** - if you see runtime guard warnings frequently, fix your `.env` file permanently

## Files Modified

| File | Purpose | Layer |
|------|---------|-------|
| `scripts/validate_env.sh` | Proactive validation script | 1 |
| `Makefile` | Integrates validation into workflows | 1 |
| `app/flask_app.py` | Flask app runtime guard | 2 |
| `app/provisioning_service.py` | Service layer runtime guard | 2 |
| `gunicorn.conf.py` | Worker process runtime guard | 2 |
| `scripts/demo_jml.sh` | Bash script runtime guard | 2 |

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ User Action                                                     │
└────────┬────────────────────────────────────────────────────────┘
         │
         ├─ make fresh-demo ───► validate_env.sh ───► Fix .env ───┐
         │                         (Layer 1)                       │
         ├─ make quickstart ───► validate_env.sh ───► Fix .env ───┤
         │                         (Layer 1)                       │
         │                                                         │
         ├─ docker-compose up ────────────────────────────────────┤
         │   (bypasses validation)                                │
         │                                                         │
         └─ ./scripts/demo_jml.sh ────────────────────────────────┤
             (bypasses validation)                                │
                                                                   ▼
         ┌─────────────────────────────────────────────────────────┐
         │ Runtime Execution                                       │
         │   - Python: flask_app.py, provisioning_service.py      │
         │   - Gunicorn: gunicorn.conf.py                         │
         │   - Bash: demo_jml.sh                                  │
         │                                                         │
         │ ✅ Runtime Guards (Layer 2) correct in-memory          │
         └─────────────────────────────────────────────────────────┘
```

## Rationale: Why Keep Both Layers?

**Q: Can't we just rely on `validate_env.sh` and remove runtime guards?**

**A: No.** Here's why:

1. **Not all users use `make`** - Some prefer direct Docker commands
2. **Scripts can run standalone** - `demo_jml.sh` doesn't always go through make
3. **Human error protection** - Someone might edit `.env` after validation
4. **CI/CD compatibility** - Automated pipelines might not run `make validate-env`
5. **Principle of least surprise** - The code itself documents and enforces the constraint
6. **Zero-trust architecture** - Don't assume the environment is correct; verify at runtime

The small cost of a few if-statements is worth the robustness.
