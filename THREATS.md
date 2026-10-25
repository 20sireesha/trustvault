# TrustVault threat model

Last reviewed: 2026-10-24

This is a demo threat model. Update it when code changes and distinguish tested controls from planned controls.

## Assets and trust boundaries
- Confidential file bytes and metadata.
- User credentials and active session.
- Per-document grants.
- Audit events needed for incident review.
- Trust boundary: every browser request is untrusted; only server-side checks authorize access.
- Storage boundary: files are kept in `private_data/uploads`, not under `static/`, and are delivered only through a checked route.

## Threats, controls, tests, residual risk

| Threat | Mitigation in this demo | Test/evidence | Residual risk / accepted decision |
|---|---|---|---|
| Guess document IDs (IDOR) to view another user's metadata | `require_doc_permission()` on detail route; no trust in hidden UI | `test_ungranted_user_cannot_view_download_edit_or_delete` | Admin intentionally has global access |
| Direct download URL bypasses page checks | Download route independently checks permission before reading bytes | Same cross-user test covers download | Downloaded copies cannot be recalled |
| POST directly to edit/delete endpoints | Permission is checked server-side in each handler; delete is POST only | Same cross-user test checks edit and delete | No document-content editing; metadata only |
| Grant permission to self/another person without authority | Grant/revoke requires owner or admin; validates target and permission | Add more adversarial tests before production | Admin can change grants by design |
| Revoked link or old URL still works | URLs are not bearer tokens; every download uses current DB grant | `test_grant_then_revoke_blocks_next_request` | Existing downloaded copies remain outside control |
| Unauthorized user learns whether a document ID exists | Unknown ID returns 404; existing-but-denied currently returns 403 | Detail/download paths tested | 403 vs 404 can reveal existence; normalize to 404 in a hardened deployment |
| Cross-site request forgery | Flask-WTF CSRF token on forms; state-changing actions use POST | Manual check; test client disables CSRF for focused auth tests | No dedicated CSRF integration test yet |
| Malicious filename/path traversal | `secure_filename`; random server-side storage name; client filename never used as path | Upload route review | Archive/polyglot and parser attacks need deeper inspection |
| Spoofed file extension / oversized file | Allowlist, 10 MB limit, basic PDF/PNG/JPEG signature checks | Manual upload checks | DOCX/XLSX/CSV are not deeply parsed; no antivirus scan |
| Stored file exposed as static URL | Private storage directory and authenticated download route | Review `UPLOAD_DIR` and `download()` | Host filesystem permissions and backups still matter |
| Audit row modified after incident | Each entry hashes its canonical fields and prior hash; admin can run chain verification | `/admin/audit/verify` | DB owner can rewrite entire chain; external immutable log sink is not implemented |
| Denied access attempts missing from audit | Authorization failure handler writes `authorization_denied` event before abort | `test_denied_attempt_is_audited` | Infrastructure failures can prevent log writes; alerting not built |
| Password guessing | Passwords are hashed with Werkzeug; failed attempts logged | Login code review | Rate limiting, lockout, MFA and alerting are not implemented |
| Session theft / cookie misuse | HTTP-only, SameSite=Lax cookies; secure cookie can be enabled behind HTTPS | Header/config review | Set `TRUSTVAULT_HTTPS=1` in HTTPS deployment; no MFA |
| SQL injection | All user values passed through SQLite parameter placeholders | Code review | Keep parameterized-query rule in future changes |
| XSS in titles/details | Jinja auto-escapes HTML output; CSP response header | Code review | Do not add `safe` for user-controlled values |
| Audit data leakage | Admin route is role-gated | `test_non_admin_cannot_read_admin_audit` | Admin account compromise exposes audit data |
| Concurrent grant/revoke race | Each request checks live database grants | Revocation test | In-flight response begun before revocation may finish; no distributed cache exists |
| Backup theft / disk access | No public static route to files | Deployment review | At-rest encryption, access-controlled backups and key management are deployment responsibilities |
| Admin misuse / insider threat | Admin actions are logged where supported | Admin audit page | No dual approval, immutable external sink, or alert on privileged access |
| Account removed but session still active | Demo has no user disable feature | Not implemented | Must add account disable/session versioning before production |
| Resource exhaustion | Per-file size cap | Manual test | No rate limits, quota, total storage cap or upload throttling |
| Supply-chain/dependency risk | Small dependency list | `requirements.txt` | Pin versions, scan dependencies and update regularly before production |

## Deliberately not built
- External sharing links: bearer links are easy to leak; start with named authenticated accounts.
- Folder inheritance and groups: direct per-document grants are easier to reason about and test for a first version.
- Document content editing and version history: this demo edits metadata only to keep the write surface small.
- AI permission recommendations: not needed to meet the security floor; if added later, suggestions must never grant access automatically and both suggestion and human decision must be audited.
- Production-grade immutable audit: requires a separately administered append-only destination, retention policy, monitoring and operational ownership.
- Malware scanning, MFA, rate limiting, account recovery and formal compliance controls: required before real confidential use.
