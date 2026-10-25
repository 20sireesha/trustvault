# TrustVault — secure document sharing starter

TrustVault is a small Flask + SQLite web application demonstrating **server-side, per-document authorization**. It is a learning/demo project, not a production-certified document management system.

## Features
- Three roles: administrator, owner, viewer.
- Owners upload, edit metadata, soft-delete, grant read/edit access, and revoke access per document.
- Viewers can only see documents explicitly shared with them.
- Download routes re-check permission on every request; files are stored outside Flask's static directory under `private_data/uploads`.
- Search by title, owner, category, and date.
- CSRF protection, secure random stored filenames, 10 MB upload limit, extension allowlist, basic signature checks for PDF/PNG/JPEG.
- Audit events include successful downloads, metadata changes, deletion, grants/revocations, login failures, and denied authorization attempts.
- Hash-chained audit entries with a verification page.
- Automated tests for cross-user access, revocation, role restrictions and audit recording.

## Demo accounts
| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin123!` |
| Document owner | `owner` | `Owner123!` |
| Viewer | `viewer` | `Viewer123!` |

**Demo credentials only. Change/remove them before deployment. Never upload real confidential files to a public demo.**

## Run on Windows (VS Code)
1. Install Python 3.11+ from https://www.python.org/downloads/ and select **Add Python to PATH**.
2. Extract this folder and open it in VS Code: **File → Open Folder → TrustVault**.
3. Open **Terminal → New Terminal**.
4. Create a virtual environment:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks activation, use Command Prompt terminal and run:
   ```bat
   .venv\Scripts\activate.bat
   ```
5. Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```
6. Start the server:
   ```powershell
   python app.py
   ```
7. Open **http://127.0.0.1:5000** in Chrome. This is your local development server, not a public live deployment.

## Test the security
In another terminal with the virtual environment activated:
```powershell
python -m pytest -q
```
Tests should pass. If you change authorization code, run them again.

## Quick demo flow
1. Sign in as `owner` and upload a harmless test `.txt` file.
2. Open the document and grant `viewer` read access.
3. Sign out; sign in as `viewer`; open/download the granted file.
4. Try a document ID owned by someone else that was not shared. The server should deny it.
5. Sign out and return as `owner`; revoke viewer access.
6. Sign in as `viewer` again and retry the download. It should now fail.
7. Sign in as `admin`; open **Admin audit** and filter `permission_granted`, `permission_revoked`, `download`, or `authorization_denied`. Try **Verify hash chain**.

## Deployment (public live URL)
For a safe public deployment, use a platform that supports Python web apps and persistent private storage, or deploy to a VM/container with persistent disk. A basic deployment checklist:
1. Push this repository to GitHub.
2. Choose a Python host (for example Render, Railway, or a small cloud VM) and connect the repository.
3. Build/install command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app` (add `gunicorn` to `requirements.txt` first).
5. Set environment variables:
   - `TRUSTVAULT_SECRET_KEY`: a long random secret, never commit it.
   - `TRUSTVAULT_HTTPS=1` when behind HTTPS.
   - `TRUSTVAULT_DATA_DIR`: a persistent disk directory writable by the app.
   - `TRUSTVAULT_DEBUG=0`
6. Use persistent disk for SQLite and uploads. Some free hosts use ephemeral disks; data will disappear on redeploy/restart if you do not configure persistence.
7. Disable demo accounts and create real users with a secure admin-only provisioning flow before public use. Configure HTTPS.
8. Re-run tests and manually test access-denial/revocation against the deployed URL.

A live URL cannot be created from your computer automatically by this project archive; you must deploy it to a hosting provider and configure the environment there.

## Important security limitations (read before deployment)
- This starter is intentionally not a production-ready vault. It has no malware scanning, no external immutable audit sink, no account lockout/MFA/password reset, no version history, and no robust account provisioning UI.
- The hash chain is **tamper-evident, not tamper-proof**: a database administrator could rewrite all rows and recompute hashes. Production should stream events to separately administered append-only storage and alert on chain verification failures.
- A download already saved by a user cannot be recalled. Revocation blocks future server requests immediately; it cannot erase downloaded copies.
- The administrator can access all documents by design. For a real environment, document and justify this break-glass privilege.
- Basic file signature checks are not complete content validation and do not scan for malware. Use a maintained file inspection/AV service before accepting untrusted uploads.
- SQLite is suitable for a demo, not multi-instance production hosting. Use managed PostgreSQL and object storage with private buckets, short-lived authorized downloads or an authenticated streaming endpoint, and audit every access.
- The app records failed logins, but this demo does not implement rate limiting or account lockout.
- The app does not promise legal compliance or a specific retention standard.

## Project layout
- `app.py` — Flask routes, authorization checks, audit trail, SQLite schema initialization.
- `templates/` — HTML screens.
- `static/style.css` — responsive visual design.
- `tests/test_security.py` — security regression tests.
- `THREATS.md` — threat model, mitigations and accepted risks.
- `PROMPTS.md` — dated AI-assisted development log; update honestly as you work and link actual commits.

## API/route access summary
This starter is server-rendered rather than a JSON REST API.

| Route | Who may call it | Notes |
|---|---|---|
| `GET /login`, `POST /login` | Anyone | Login attempts are audited |
| `POST /logout` | Signed-in users | CSRF protected |
| `GET /documents` | Signed-in users | Own + explicitly granted docs; admin sees all |
| `GET,POST /upload` | Owner, admin | Validates basic file properties |
| `GET /documents/<id>` | Owner, admin, or granted read/edit user | Metadata view |
| `GET /documents/<id>/download` | Owner, admin, or granted read/edit user | Re-checks access on every request |
| `POST /documents/<id>/edit` | Owner, admin, or edit-granted user | Metadata only |
| `POST /documents/<id>/grant` | Owner, admin | Permission changes audited |
| `POST /documents/<id>/revoke/<user_id>` | Owner, admin | Revocation audited |
| `POST /documents/<id>/delete` | Owner, admin | Soft delete |
| `GET /admin`, `GET /admin/audit/verify` | Admin | Activity log and hash-chain verification |
