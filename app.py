import os, sqlite3, secrets, time, mimetypes
from pathlib import Path
from flask import Flask, request, jsonify, abort, render_template, send_file, make_response, after_this_request
from werkzeug.utils import secure_filename

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("DATA_DIR", BASE / "data"))
UPLOADS = DATA / "uploads"
DB = DATA / "links.sqlite3"
MAX_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 25 * 1024 * 1024))
DEFAULT_TTL = int(os.environ.get("DEFAULT_TTL_SECONDS", 24 * 60 * 60))

DATA.mkdir(parents=True, exist_ok=True)
UPLOADS.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES

def connect():
    db = sqlite3.connect(DB, timeout=15)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with connect() as db:
        db.execute("""
          CREATE TABLE IF NOT EXISTS links (
            token TEXT PRIMARY KEY,
            stored_name TEXT NOT NULL,
            original_name TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            used_at INTEGER
          )
        """)
init_db()

@app.get("/")
def home():
    return render_template("index.html", max_mb=MAX_BYTES // (1024 * 1024))

@app.post("/api/upload")
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="Επίλεξε αρχείο."), 400

    original = secure_filename(f.filename) or "file"
    mime = f.mimetype or mimetypes.guess_type(original)[0] or "application/octet-stream"
    # Inline viewing is limited to common browser-previewable formats.
    allowed = {"application/pdf", "image/png", "image/jpeg", "image/gif", "image/webp", "text/plain"}
    if mime not in allowed:
        return jsonify(error="Υποστηρίζονται PDF, εικόνες PNG/JPEG/GIF/WebP και απλό κείμενο."), 415

    ttl_raw = request.form.get("ttl", str(DEFAULT_TTL))
    try:
        ttl = max(60, min(int(ttl_raw), 7 * 24 * 60 * 60))
    except ValueError:
        ttl = DEFAULT_TTL

    token = secrets.token_urlsafe(24)
    stored = secrets.token_hex(24)
    path = UPLOADS / stored
    f.save(path)

    now = int(time.time())
    try:
        with connect() as db:
            db.execute(
                "INSERT INTO links(token, stored_name, original_name, mime_type, created_at, expires_at) VALUES(?,?,?,?,?,?)",
                (token, stored, original, mime, now, now + ttl)
            )
    except Exception:
        path.unlink(missing_ok=True)
        raise

    return jsonify(url=request.host_url.rstrip("/") + "/v/" + token, expires_in=ttl)

@app.get("/v/<token>")
def view_once(token):
    # Atomic claim: only one concurrent request can acquire a token.
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM links WHERE token=?", (token,)).fetchone()
        now = int(time.time())
        if not row or row["used_at"] is not None or row["expires_at"] <= now:
            db.rollback()
            abort(404)
        changed = db.execute(
            "UPDATE links SET used_at=? WHERE token=? AND used_at IS NULL AND expires_at>?",
            (now, token, now)
        ).rowcount
        if changed != 1:
            db.rollback()
            abort(404)
        db.commit()

    path = UPLOADS / row["stored_name"]
    if not path.is_file():
        abort(404)

    @after_this_request
    def remove_file(response):
        path.unlink(missing_ok=True)
        # Remove metadata too; link stays invalid because its record is gone.
        with connect() as db:
            db.execute("DELETE FROM links WHERE token=?", (token,))
        return response

    response = make_response(send_file(
        path,
        mimetype=row["mime_type"],
        as_attachment=False,
        download_name=row["original_name"],
        conditional=False,
        max_age=0
    ))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; sandbox"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

@app.errorhandler(413)
def too_large(_):
    return jsonify(error=f"Το αρχείο ξεπερνά το όριο των {MAX_BYTES // (1024*1024)} MB."), 413

@app.errorhandler(404)
def not_found(_):
    return render_template("gone.html"), 404

if __name__ == "__main__":
    # For local testing only. Use a production WSGI server when deployed.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
