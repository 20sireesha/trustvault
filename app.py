import os, sqlite3, hashlib, json, mimetypes, secrets
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("TRUSTVAULT_DATA_DIR", BASE / "private_data"))
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = Path(os.environ.get("TRUSTVAULT_DB", DATA_DIR / "trustvault.sqlite3"))
MAX_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg", "docx", "xlsx", "csv"}
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("TRUSTVAULT_SECRET_KEY", "dev-only-change-this-before-deploying"),
    MAX_CONTENT_LENGTH=MAX_BYTES + 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("TRUSTVAULT_HTTPS", "0") == "1",
)
CSRFProtect(app)

def now():
    return datetime.now(timezone.utc).isoformat()

def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer'))
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL,
            original_name TEXT NOT NULL, stored_name TEXT UNIQUE NOT NULL,
            owner_id INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
            deleted_at TEXT
        );
        CREATE TABLE IF NOT EXISTS grants (
            id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL REFERENCES documents(id),
            user_id INTEGER NOT NULL REFERENCES users(id), permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
            created_at TEXT NOT NULL, UNIQUE(document_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor_id INTEGER, actor_name TEXT NOT NULL,
            action TEXT NOT NULL, document_id INTEGER, details TEXT NOT NULL,
            previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents(owner_id);
        CREATE INDEX IF NOT EXISTS idx_docs_created ON documents(created_at);
        CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at);
        """)
        seeds = [
            ("admin", "Admin123!", "admin"),
            ("owner", "Owner123!", "owner"),
            ("viewer", "Viewer123!", "viewer"),
        ]
        for username, password, role in seeds:
            db.execute("INSERT OR IGNORE INTO users(username,password_hash,role) VALUES(?,?,?)",
                       (username, generate_password_hash(password), role))

def audit(actor_id, action, document_id=None, details=None):
    # Hash chaining makes edits detectable; production must additionally export/anchor logs
    # to a separate append-only system because a DB administrator could rewrite the chain.
    with connect() as db:
        user = db.execute("SELECT username FROM users WHERE id=?", (actor_id,)).fetchone() if actor_id else None
        actor_name = user["username"] if user else "anonymous"
        last = db.execute("SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["entry_hash"] if last else "GENESIS"
        at = now()
        payload = json.dumps({"at":at,"actor_id":actor_id,"actor_name":actor_name,"action":action,
                              "document_id":document_id,"details":details or {},"previous_hash":prev},
                             sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode()).hexdigest()
        db.execute("""INSERT INTO audit(at,actor_id,actor_name,action,document_id,details,previous_hash,entry_hash)
                      VALUES(?,?,?,?,?,?,?,?)""",
                   (at,actor_id,actor_name,action,document_id,json.dumps(details or {},sort_keys=True),prev,digest))

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with connect() as db:
        return db.execute("SELECT id,username,role FROM users WHERE id=?", (uid,)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if user["role"] not in roles:
                audit(user["id"], "authorization_denied", kwargs.get("doc_id"), {"path":request.path,"required_roles":roles})
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def get_doc(doc_id, include_deleted=False):
    with connect() as db:
        query = "SELECT d.*,u.username AS owner_name FROM documents d JOIN users u ON u.id=d.owner_id WHERE d.id=?"
        if not include_deleted:
            query += " AND d.deleted_at IS NULL"
        return db.execute(query, (doc_id,)).fetchone()

def permission_for(user, doc):
    if not user or not doc:
        return None
    if user["role"] == "admin" or user["id"] == doc["owner_id"]:
        return "edit"
    with connect() as db:
        row = db.execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",
                         (doc["id"], user["id"])).fetchone()
    return row["permission"] if row else None

def require_doc_permission(doc_id, minimum="read"):
    user = current_user()
    doc = get_doc(doc_id)
    permission = permission_for(user, doc) if doc else None
    allowed = permission == "edit" or (minimum == "read" and permission == "read")
    if not allowed:
        audit(user["id"] if user else None, "authorization_denied", doc_id,
              {"path":request.path,"required":minimum})
        abort(404 if not doc else 403)
    return user, doc

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"
    return response

@app.route("/")
def index():
    if not current_user():
        return redirect(url_for("login"))
    return redirect(url_for("documents"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        with connect() as db:
            user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            audit(user["id"], "login_success", details={"username":username})
            return redirect(url_for("documents"))
        audit(None, "login_failed", details={"username":username[:80]})
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    user = current_user()
    audit(user["id"], "logout")
    session.clear()
    return redirect(url_for("login"))

@app.route("/documents")
@login_required
def documents():
    user = current_user()
    q = request.args.get("q","").strip()[:100]
    category = request.args.get("category","").strip()[:80]
    owner = request.args.get("owner","").strip()[:80]
    date_from = request.args.get("from","")[:10]
    date_to = request.args.get("to","")[:10]
    sql = """SELECT DISTINCT d.*,u.username AS owner_name FROM documents d
             JOIN users u ON u.id=d.owner_id LEFT JOIN grants g ON g.document_id=d.id
             WHERE d.deleted_at IS NULL AND (d.owner_id=? OR g.user_id=? OR ?)"""
    params = [user["id"], user["id"], 1 if user["role"]=="admin" else 0]
    if q:
        sql += " AND d.title LIKE ?"; params.append("%"+q+"%")
    if category:
        sql += " AND d.category LIKE ?"; params.append("%"+category+"%")
    if owner:
        sql += " AND u.username LIKE ?"; params.append("%"+owner+"%")
    if date_from:
        sql += " AND substr(d.created_at,1,10)>=?"; params.append(date_from)
    if date_to:
        sql += " AND substr(d.created_at,1,10)<=?"; params.append(date_to)
    sql += " ORDER BY d.created_at DESC"
    with connect() as db:
        docs = db.execute(sql, params).fetchall()
    # Hide rows for grants that might have been revoked between query and rendering.
    docs = [d for d in docs if permission_for(user,d)]
    return render_template("documents.html", user=user, docs=docs, q=q, category=category, owner=owner,
                           date_from=date_from, date_to=date_to)

@app.route("/upload", methods=["GET","POST"])
@login_required
@role_required("owner","admin")
def upload():
    user = current_user()
    if request.method == "POST":
        f = request.files.get("file")
        title = request.form.get("title","").strip()[:160]
        category = request.form.get("category","General").strip()[:80] or "General"
        if not f or not f.filename or not title:
            flash("Choose a file and enter a title.", "error")
            return redirect(url_for("upload"))
        original = secure_filename(f.filename)
        ext = original.rsplit(".",1)[-1].lower() if "." in original else ""
        if ext not in ALLOWED_EXTENSIONS:
            flash("File type not allowed. Allowed: " + ", ".join(sorted(ALLOWED_EXTENSIONS)), "error")
            return redirect(url_for("upload"))
        raw = f.read(MAX_BYTES + 1)
        if not raw or len(raw) > MAX_BYTES:
            flash("Files must be between 1 byte and 10 MB.", "error")
            return redirect(url_for("upload"))
        # Basic signature checks for common binary types; not a substitute for malware scanning.
        signatures = {"pdf": b"%PDF-", "png": b"\\x89PNG\\r\\n\\x1a\\n", "jpg": b"\\xff\\xd8\\xff", "jpeg": b"\\xff\\xd8\\xff"}
        if ext in signatures and not raw.startswith(signatures[ext]):
            flash("The file contents do not match the file extension.", "error")
            return redirect(url_for("upload"))
        stored = secrets.token_hex(24) + "." + ext
        path = UPLOAD_DIR / stored
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        try:
            with connect() as db:
                cur = db.execute("""INSERT INTO documents(title,category,original_name,stored_name,owner_id,created_at,updated_at,sha256,size)
                                    VALUES(?,?,?,?,?,?,?,?,?)""",
                                 (title,category,original,stored,user["id"],now(),now(),digest,len(raw)))
                doc_id = cur.lastrowid
            audit(user["id"], "upload", doc_id, {"title":title,"filename":original,"sha256":digest,"size":len(raw)})
        except Exception:
            path.unlink(missing_ok=True)
            raise
        flash("Document uploaded.", "success")
        return redirect(url_for("document_detail", doc_id=doc_id))
    return render_template("upload.html", user=user)

@app.route("/documents/<int:doc_id>")
@login_required
def document_detail(doc_id):
    user, doc = require_doc_permission(doc_id, "read")
    with connect() as db:
        grants = db.execute("""SELECT g.user_id,g.permission,g.created_at,u.username FROM grants g
                               JOIN users u ON u.id=g.user_id WHERE g.document_id=? ORDER BY u.username""",
                            (doc_id,)).fetchall()
        users = db.execute("SELECT id,username,role FROM users WHERE id<>? ORDER BY username", (doc["owner_id"],)).fetchall()
    audit(user["id"], "view_metadata", doc_id, {"title":doc["title"]})
    return render_template("detail.html", user=user, doc=doc, permission=permission_for(user,doc),
                           grants=grants, users=users, can_manage=(user["id"]==doc["owner_id"] or user["role"]=="admin"))

@app.route("/documents/<int:doc_id>/download")
@login_required
def download(doc_id):
    user, doc = require_doc_permission(doc_id, "read")
    path = UPLOAD_DIR / doc["stored_name"]
    if not path.is_file():
        audit(user["id"], "download_missing_file", doc_id, {})
        abort(404)
    audit(user["id"], "download", doc_id, {"sha256":doc["sha256"]})
    return send_file(path, as_attachment=True, download_name=doc["original_name"], mimetype="application/octet-stream")

@app.route("/documents/<int:doc_id>/edit", methods=["POST"])
@login_required
def edit_document(doc_id):
    user, doc = require_doc_permission(doc_id, "edit")
    title = request.form.get("title","").strip()[:160]
    category = request.form.get("category","").strip()[:80]
    if not title or not category:
        flash("Title and category are required.", "error")
        return redirect(url_for("document_detail", doc_id=doc_id))
    with connect() as db:
        db.execute("UPDATE documents SET title=?,category=?,updated_at=? WHERE id=?",
                   (title,category,now(),doc_id))
    audit(user["id"], "metadata_change", doc_id, {"before":{"title":doc["title"],"category":doc["category"]},
                                                  "after":{"title":title,"category":category}})
    flash("Document details updated.", "success")
    return redirect(url_for("document_detail", doc_id=doc_id))

@app.route("/documents/<int:doc_id>/grant", methods=["POST"])
@login_required
def grant_access(doc_id):
    user, doc = require_doc_permission(doc_id, "edit")
    if user["id"] != doc["owner_id"] and user["role"] != "admin":
        abort(403)
    target = request.form.get("user_id","")
    permission = request.form.get("permission","read")
    if permission not in ("read","edit"):
        abort(400)
    with connect() as db:
        target_user = db.execute("SELECT id,username,role FROM users WHERE id=?", (target,)).fetchone()
        if not target_user or target_user["id"] == doc["owner_id"]:
            flash("Choose a valid user.", "error")
            return redirect(url_for("document_detail",doc_id=doc_id))
        db.execute("""INSERT INTO grants(document_id,user_id,permission,created_at) VALUES(?,?,?,?)
                      ON CONFLICT(document_id,user_id) DO UPDATE SET permission=excluded.permission,created_at=excluded.created_at""",
                   (doc_id,target_user["id"],permission,now()))
    audit(user["id"], "permission_granted", doc_id, {"target":target_user["username"],"permission":permission})
    flash("Access granted. The change applies to the next request.", "success")
    return redirect(url_for("document_detail",doc_id=doc_id))

@app.route("/documents/<int:doc_id>/revoke/<int:target_id>", methods=["POST"])
@login_required
def revoke_access(doc_id,target_id):
    user, doc = require_doc_permission(doc_id, "edit")
    if user["id"] != doc["owner_id"] and user["role"] != "admin":
        abort(403)
    with connect() as db:
        target = db.execute("SELECT username FROM users WHERE id=?", (target_id,)).fetchone()
        db.execute("DELETE FROM grants WHERE document_id=? AND user_id=?", (doc_id,target_id))
    audit(user["id"], "permission_revoked", doc_id, {"target":target["username"] if target else str(target_id)})
    flash("Access revoked. Future requests are denied immediately; downloaded copies cannot be recalled.", "success")
    return redirect(url_for("document_detail",doc_id=doc_id))

@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_document(doc_id):
    user, doc = require_doc_permission(doc_id, "edit")
    if user["id"] != doc["owner_id"] and user["role"] != "admin":
        abort(403)
    # Soft delete for recoverability; deleted docs are hidden from ordinary routes.
    with connect() as db:
        db.execute("UPDATE documents SET deleted_at=? WHERE id=?", (now(),doc_id))
        db.execute("DELETE FROM grants WHERE document_id=?", (doc_id,))
    audit(user["id"], "delete", doc_id, {"title":doc["title"],"sha256":doc["sha256"],"mode":"soft-delete"})
    flash("Document moved to deleted state.", "success")
    return redirect(url_for("documents"))

@app.route("/admin")
@login_required
@role_required("admin")
def admin():
    q = request.args.get("q","").strip()[:100]
    with connect() as db:
        rows = db.execute("""SELECT id,at,actor_name,action,document_id,details,previous_hash,entry_hash
                             FROM audit WHERE action LIKE ? OR actor_name LIKE ? OR details LIKE ?
                             ORDER BY id DESC LIMIT 500""", ("%"+q+"%","%"+q+"%","%"+q+"%")).fetchall()
        counts = db.execute("SELECT action,COUNT(*) AS n FROM audit GROUP BY action ORDER BY n DESC").fetchall()
        users = db.execute("SELECT id,username,role FROM users ORDER BY role,username").fetchall()
    return render_template("admin.html",user=current_user(),rows=rows,counts=counts,users=users,q=q)

@app.route("/admin/audit/verify")
@login_required
@role_required("admin")
def verify_audit():
    with connect() as db:
        rows = db.execute("SELECT * FROM audit ORDER BY id").fetchall()
    prev = "GENESIS"
    bad = []
    for row in rows:
        payload = json.dumps({"at":row["at"],"actor_id":row["actor_id"],"actor_name":row["actor_name"],
                              "action":row["action"],"document_id":row["document_id"],
                              "details":json.loads(row["details"]),"previous_hash":row["previous_hash"]},
                             sort_keys=True,separators=(",",":"))
        expected = hashlib.sha256(payload.encode()).hexdigest()
        if row["previous_hash"] != prev or row["entry_hash"] != expected:
            bad.append(row["id"])
        prev = row["entry_hash"]
    audit(current_user()["id"], "audit_chain_verified", details={"valid":not bad,"bad_rows":bad})
    return render_template("verify.html", user=current_user(), bad=bad, total=len(rows))

@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="You do not have permission to do that."), 403

@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="This resource is unavailable."), 404

@app.errorhandler(413)
def too_large(_):
    return render_template("error.html", code=413, message="Upload too large. Maximum file size is 10 MB."), 413

init_db()
if __name__ == "__main__":
    app.run(debug=os.environ.get("TRUSTVAULT_DEBUG","0") == "1", port=int(os.environ.get("PORT","5000")))