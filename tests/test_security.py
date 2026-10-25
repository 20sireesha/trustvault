import os, tempfile, importlib
import pytest

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTVAULT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("TRUSTVAULT_SECRET_KEY", "test-secret-key-not-for-production")
    import app as tv
    tv.DATA_DIR = tmp_path / "data"
    tv.UPLOAD_DIR = tv.DATA_DIR / "uploads"
    tv.DB_PATH = tv.DATA_DIR / "test.sqlite3"
    tv.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    tv.init_db()
    tv.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, SECRET_KEY="test-secret")
    with tv.app.test_client() as c:
        yield c, tv

def login(client, username, password):
    return client.post("/login", data={"username":username,"password":password}, follow_redirects=True)

def test_viewer_cannot_upload(client):
    c,tv=client
    login(c,"viewer","Viewer123!")
    assert c.get("/upload").status_code == 403

def test_ungranted_user_cannot_view_download_edit_or_delete(client):
    c,tv=client
    login(c,"owner","Owner123!")
    response=c.post("/upload", data={"title":"Owner secret","category":"Legal",
        "file":( __import__("io").BytesIO(b"secret document"),"secret.txt")}, content_type="multipart/form-data")
    assert response.status_code == 302
    with tv.connect() as db:
        doc=db.execute("SELECT id FROM documents WHERE title='Owner secret'").fetchone()
    doc_id=doc["id"]
    c.post("/logout")
    login(c,"viewer","Viewer123!")
    assert c.get(f"/documents/{doc_id}").status_code in (403,404)
    assert c.get(f"/documents/{doc_id}/download").status_code in (403,404)
    assert c.post(f"/documents/{doc_id}/edit",data={"title":"stolen","category":"x"}).status_code in (403,404)
    assert c.post(f"/documents/{doc_id}/delete").status_code in (403,404)
    with tv.connect() as db:
        row=db.execute("SELECT title,deleted_at FROM documents WHERE id=?",(doc_id,)).fetchone()
    assert row["title"] == "Owner secret"
    assert row["deleted_at"] is None

def test_grant_then_revoke_blocks_next_request(client):
    c,tv=client
    login(c,"owner","Owner123!")
    c.post("/upload", data={"title":"Shareable","category":"General",
        "file":(__import__("io").BytesIO(b"hello"),"hello.txt")}, content_type="multipart/form-data")
    with tv.connect() as db:
        doc=db.execute("SELECT id FROM documents WHERE title='Shareable'").fetchone()
        viewer=db.execute("SELECT id FROM users WHERE username='viewer'").fetchone()
    doc_id, viewer_id=doc["id"],viewer["id"]
    c.post(f"/documents/{doc_id}/grant",data={"user_id":viewer_id,"permission":"read"})
    c.post("/logout")
    login(c,"viewer","Viewer123!")
    assert c.get(f"/documents/{doc_id}/download").status_code == 200
    c.post("/logout")
    login(c,"owner","Owner123!")
    c.post(f"/documents/{doc_id}/revoke/{viewer_id}")
    c.post("/logout")
    login(c,"viewer","Viewer123!")
    assert c.get(f"/documents/{doc_id}/download").status_code in (403,404)

def test_non_admin_cannot_read_admin_audit(client):
    c,tv=client
    login(c,"viewer","Viewer123!")
    assert c.get("/admin").status_code == 403

def test_denied_attempt_is_audited(client):
    c,tv=client
    login(c,"owner","Owner123!")
    c.post("/upload", data={"title":"Private","category":"General",
        "file":(__import__("io").BytesIO(b"private"),"private.txt")}, content_type="multipart/form-data")
    with tv.connect() as db:
        doc=db.execute("SELECT id FROM documents WHERE title='Private'").fetchone()
    c.post("/logout")
    login(c,"viewer","Viewer123!")
    c.get(f"/documents/{doc['id']}")
    with tv.connect() as db:
        denied=db.execute("SELECT COUNT(*) n FROM audit WHERE action='authorization_denied'").fetchone()["n"]
    assert denied >= 1
