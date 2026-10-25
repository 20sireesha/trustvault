# AI-assisted development log

Keep this file truthful and update it throughout development. Replace example commit links with actual commit hashes from your repository. Do not claim a fix or test was completed until you did it.

## 2026-10-24 — Initial architecture
- **Prompt / summary:** Build a beginner-friendly TrustVault demo with Flask, per-document grants, private file storage, audit events, tests, setup instructions and a threat model.
- **Produced:** Flask app, SQLite schema, HTML templates, test skeleton and documentation.
- **What was wrong / checked:** A CRUD scaffold alone would be unsafe if the list page hid files but download routes did not check grants. I reviewed each document route and centralized the check in `require_doc_permission()`, then also invoked it inside download/edit/grant/revoke/delete handlers.
- **What I did instead:** Added route-level checks and cross-user tests. Commit link: TODO — replace with actual commit URL after committing this change.

## 2026-10-24 — Authorization / IDOR review
- **Prompt / summary:** Review the app for insecure direct object reference and direct-route bypasses. Assume a viewer guesses another document ID and calls GET and POST routes manually.
- **Produced:** Suggested checking document access on each endpoint.
- **What was wrong / checked:** A UI-only permission check would not protect a direct download URL or a forged POST. I checked the detail, download, edit, grant, revoke and delete routes separately.
- **What I did instead:** Added `test_ungranted_user_cannot_view_download_edit_or_delete` and role restriction tests. Commit link: TODO — replace with actual commit URL after committing this change.

## 2026-10-24 — Revocation semantics
- **Prompt / summary:** Explain how to make revocation immediate when users have previously opened a document.
- **Produced:** Check the permission database when each request arrives; do not use long-lived public links.
- **What was wrong / checked:** Revocation cannot erase a file already downloaded to a recipient's device, and an in-flight response may already have started. A UI message must not promise recall of copies.
- **What I did instead:** Downloads are authenticated requests with a live grant check; the UI and README state the limitation. Added `test_grant_then_revoke_blocks_next_request`. Commit link: TODO — replace with actual commit URL after committing this change.

## 2026-10-24 — Audit integrity
- **Prompt / summary:** Add an audit trail for successful and denied actions and explain how to detect edits.
- **Produced:** Hash-linked audit entries and an admin verification page.
- **What was wrong / checked:** A hash chain stored only in the same writable database is not truly immutable; an attacker with database write access can rewrite the chain.
- **What I did instead:** Documented it as tamper-evident only, added chain verification, and specified a separate append-only external sink as a production requirement. Commit link: TODO — replace with actual commit URL after committing this change.

## 2026-10-24 — Upload validation
- **Prompt / summary:** Validate uploaded files and keep uploaded content from being served as static assets.
- **Produced:** Extension allowlist, size limit, random server-side name and limited signature checks.
- **What was wrong / checked:** File extensions and a few signatures are not malware scanning or comprehensive file parsing, especially for DOCX/XLSX and polyglot files.
- **What I did instead:** Kept storage private, documented the residual risk and added clear limits in README/THREATS.md. Production needs maintained content inspection and antivirus scanning. Commit link: TODO — replace with actual commit URL after committing this change.

## Reusable development context
- Treat all browser input as untrusted.
- Authorization must happen server-side on every endpoint and every object ID.
- Do not treat obscured buttons, hard-to-guess IDs, or hidden links as authorization.
- Never claim a security property without a test or a clearly stated residual risk.
- Use AI output as a proposal; review the implementation, run tests, and record specific mistakes.
