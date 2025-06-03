# run.py
from app import create_app
import os
import hmac
import hashlib
import json
from datetime import datetime

from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from mongoengine import connect
from dotenv import load_dotenv

# ─── Load .env ───
# Make sure you have a .env file in the project root containing:
#   MONGO_URI=<your_mongo_uri>
#   GITHUB_SECRET=<your_webhook_secret>
#   FLASK_PORT=5000
load_dotenv()
MONGO_URI     = os.getenv("MONGO_URI", "mongodb://localhost:27017/github_events_db")
GITHUB_SECRET = os.getenv("GITHUB_SECRET", "").encode("utf-8")  # bytes for HMAC
FLASK_PORT    = int(os.getenv("FLASK_PORT", 5000))

# ─── Initialize Flask ───
app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)

# ─── Connect to MongoDB ───
connect(host=MONGO_URI)

# ─── Import the model ───
from models import GitHubEvent

def verify_github_signature(request):
    """
    Verifies the 'X-Hub-Signature-256' header from GitHub using HMAC-SHA256.
    If GITHUB_SECRET is empty, this function does nothing.
    """
    signature_header = request.headers.get("X-Hub-Signature-256")
    if not signature_header:
        abort(400, "Missing X-Hub-Signature-256 header")

    try:
        sha_name, signature = signature_header.split("=", 1)
    except ValueError:
        abort(400, "Malformed X-Hub-Signature-256 header")

    if sha_name != "sha256":
        abort(400, "We only support sha256 signatures")

    mac = hmac.new(GITHUB_SECRET, msg=request.data, digestmod=hashlib.sha256)
    expected_sig = mac.hexdigest()
    if not hmac.compare_digest(expected_sig, signature):
        abort(400, "Invalid signature")


@app.route("/github-webhook", methods=["POST"])
def github_webhook():
    """
    Main endpoint to receive GitHub webhooks. We handle exactly:
      • X-GitHub-Event: "push"
      • X-GitHub-Event: "pull_request", with:
           – action == "opened"       → record a "pull_request" event
           – action == "closed" && merged == true  → record a "merge" event
    All other events (issues, releases, etc.) are ignored with a 200.
    """
    # 1) If you configured a secret, verify the signature.
    if GITHUB_SECRET:
        verify_github_signature(request)

    # 2) Parse the JSON payload
    try:
        payload = request.get_json(force=True)
    except Exception:
        abort(400, "Invalid JSON")

    event_header = request.headers.get("X-GitHub-Event", "")
    repo_full    = payload.get("repository", {}).get("full_name", "unknown/unknown")

    # Prepare variables for the new GitHubEvent document
    event_type  = None
    author      = None
    from_branch = None
    to_branch   = None
    event_time  = None

    # ─── Handle "push" ───
    if event_header == "push":
        event_type = "push"
        author     = payload["pusher"]["name"]
        ref        = payload.get("ref", "")  # e.g. "refs/heads/main"
        to_branch  = ref.replace("refs/heads/", "", 1) if ref.startswith("refs/heads/") else ref
        from_branch = None

        head = payload.get("head_commit", {})
        if head and head.get("timestamp"):
            iso_ts    = head["timestamp"]  # e.g. "2025-06-03T14:30:00Z"
            event_time = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        else:
            event_time = datetime.utcnow()

    # ─── Handle "pull_request" ───
    elif event_header == "pull_request":
        pr_action = payload.get("action", "")
        pr_data   = payload.get("pull_request", {})

        #  (A) PR opened
        if pr_action == "opened":
            event_type  = "pull_request"
            author      = pr_data["user"]["login"]
            from_branch = pr_data["head"]["ref"]
            to_branch   = pr_data["base"]["ref"]
            created_at  = pr_data.get("created_at")
            event_time  = (datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                           if created_at else datetime.utcnow())

        #  (B) PR closed & merged → treat as "merge" event
        elif pr_action == "closed" and pr_data.get("merged") == True:
            event_type  = "merge"
            author      = pr_data["merged_by"]["login"]
            from_branch = pr_data["head"]["ref"]
            to_branch   = pr_data["base"]["ref"]
            merged_at   = pr_data.get("merged_at")
            event_time  = (datetime.fromisoformat(merged_at.replace("Z", "+00:00"))
                           if merged_at else datetime.utcnow())
        else:
            # Ignore any other pull_request action (e.g. "edited", "synchronize", etc.)
            return jsonify({"msg": f"Ignored pull_request action='{pr_action}'"}), 200

    else:
        # Ignore any other GitHub event (issues, star, release, etc.)
        return jsonify({"msg": f"Ignored event type='{event_header}'"}), 200

    # ─── Validate required fields ───
    if not (event_type and author and to_branch and event_time):
        abort(400, "Missing required fields from payload")

    # ─── Save to MongoDB ───
    try:
        doc = GitHubEvent(
            event_type     = event_type,
            author         = author,
            from_branch    = from_branch,
            to_branch      = to_branch,
            timestamp      = event_time,
            repo_full_name = repo_full,
            raw_payload    = json.dumps(payload)[:16000]  # optional truncated dump
        )
        doc.save()
    except Exception as e:
        print("MongoDB save error:", e)
        abort(500, "Database error")

    return jsonify({"msg": f"Recorded {event_type} event"}), 201


@app.route("/events", methods=["GET"])
def list_events():
    """
    (Optional) Return the N most‐recent GitHubEvent documents as JSON.
    Usage: GET /events?limit=10
    """
    try:
        limit = int(request.args.get("limit", 20))
    except ValueError:
        limit = 20

    events = GitHubEvent.objects.order_by("-timestamp").limit(limit)
    out = []
    for ev in events:
        out.append({
            "id"            : str(ev.id),
            "event_type"    : ev.event_type,
            "author"        : ev.author,
            "from_branch"   : ev.from_branch,
            "to_branch"     : ev.to_branch,
            "timestamp"     : ev.timestamp.isoformat(),
            "repo_full_name": ev.repo_full_name,
        })
    return jsonify(out), 200


@app.route("/", methods=["GET"])
def serve_ui():
    """
    If you have placed an index.html under /static, this will serve it.
    Otherwise, remove this route or adjust to your front-end needs.
    """
    return app.send_static_file("index.html")


if __name__ == "__main__":
    # debug=True is fine for local development. In production, run via gunicorn.
    app.run(host="0.0.0.0", port=FLASK_PORT, debug=True)

app = create_app()

if __name__ == '__main__': 
    app.run(debug=True)
