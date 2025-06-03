# app.py
import os
import hmac
import hashlib
import json
from datetime import datetime

from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from mongoengine import connect, DoesNotExist
from dotenv import load_dotenv

# Load ENV variables from a .env (e.g. MONGO_URI, GITHUB_SECRET, FLASK_PORT)
load_dotenv()

GITHUB_SECRET = os.getenv("GITHUB_SECRET", "").encode("utf-8")  # set this in your .env
MONGO_URI     = os.getenv("MONGO_URI", "mongodb://localhost:27017/push_events_db")
FLASK_PORT    = int(os.getenv("FLASK_PORT", 5000))

# 1) Initialize Flask
app = Flask(__name__)
CORS(app)   # allow any origin by default; restrict as needed in production

# 2) Connect to MongoDB via MongoEngine
connect(host=MONGO_URI)

# 3) Import our document model
from models import PushEvent, CommitEmbedded


def verify_github_signature(request):
    """
    Verify X-Hub-Signature-256 header (if you set a GitHub webhook secret).
    If you didn't configure a secret, you can skip this check, but it's
    HIGHLY recommended in production.
    """
    signature_header = request.headers.get("X-Hub-Signature-256")
    if signature_header is None:
        abort(400, "Missing signature header")

    sha_name, signature = signature_header.split("=", 1)
    if sha_name != "sha256":
        abort(400, "Unsupported signature type")

    payload_bytes = request.data  # raw request body, as bytes
    mac = hmac.new(GITHUB_SECRET, msg=payload_bytes, digestmod=hashlib.sha256)
    expected_sig = mac.hexdigest()

    # Compare in constant time
    if not hmac.compare_digest(expected_sig, signature):
        abort(400, "Invalid signature")


@app.route("/github‐webhook", methods=["POST"])
def handle_github_webhook():
    """
    This route will be called by GitHub on every push.
    We verify the signature, then parse JSON, extract fields, and save to MongoDB.
    """
    # 1) Verify signature. (skip this if you didn’t set GITHUB_SECRET, 
    # but in prod it’s strongly recommended)
    if GITHUB_SECRET:
        verify_github_signature(request)

    # 2) Parse JSON
    try:
        payload = request.get_json(force=True)
    except Exception:
        abort(400, "Invalid JSON payload")

    # 3) Confirm it’s a “push” event
    github_event = request.headers.get("X-GitHub-Event", "")
    if github_event != "push":
        # We only care about push events here.
        return jsonify({"msg": "Ignored: not a push event"}), 200

    # 4) Extract the fields we declared in PushEvent model
    try:
        repo_full_name = payload["repository"]["full_name"]
        pusher_name   = payload["pusher"]["name"]
        pusher_email  = payload["pusher"]["email"]
        ref           = payload["ref"]  # e.g. "refs/heads/main"
        # extract branch by stripping "refs/heads/"
        branch = ref.replace("refs/heads/", "", 1)

        raw_commits = payload.get("commits", [])
        commit_docs = []
        for c in raw_commits:
            ce = CommitEmbedded(
                commit_id    = c["id"],
                message      = c["message"],
                timestamp    = datetime.fromisoformat(c["timestamp"].replace("Z", "+00:00")),
                url          = c["url"],
                author_name  = c["author"]["name"],
                author_email = c["author"]["email"],
            )
            commit_docs.append(ce)

        # 5) Create and save our PushEvent
        push_doc = PushEvent(
            repo_name   = repo_full_name,
            pusher_name = pusher_name,
            pusher_email= pusher_email,
            pushed_at   = datetime.utcnow(),
            branch      = branch,
            commits     = commit_docs,
            raw_payload = json.dumps(payload),  # optional: store entire JSON
        )
        push_doc.save()

    except KeyError as e:
        abort(400, f"Missing expected field: {e}")

    # 6) Respond success
    return jsonify({"msg": "Push event recorded"}), 201


@app.route("/events", methods=["GET"])
def list_events():
    """
    Return the most recent push events in JSON form.
    Optionally, you can accept a query param ?limit=10 to return only the last 10.
    """
    limit = int(request.args.get("limit", 20))
    # Fetch sorted by pushed_at descending
    events = PushEvent.objects.order_by("-pushed_at").limit(limit)

    # Build a list of dictionaries to jsonify
    out = []
    for ev in events:
        out.append({
            "id"          : str(ev.id),
            "repo_name"   : ev.repo_name,
            "pusher_name" : ev.pusher_name,
            "pusher_email": ev.pusher_email,
            "pushed_at"   : ev.pushed_at.isoformat(),
            "branch"      : ev.branch,
            "commits"     : [
                {
                    "commit_id"  : c.commit_id,
                    "message"    : c.message,
                    "timestamp"  : c.timestamp.isoformat(),
                    "url"        : c.url,
                    "author_name": c.author_name,
                    "author_email": c.author_email,
                }
                for c in ev.commits
            ],
        })

    return jsonify(out), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=FLASK_PORT, debug=True)
