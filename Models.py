# models.py
from datetime import datetime
from mongoengine import (
    Document, EmbeddedDocument,
    StringField, DateTimeField,
    ListField, EmbeddedDocumentField, URLField
)

class CommitEmbedded(EmbeddedDocument):
    """
    Represents a single commit inside a PushEvent.
    """
    commit_id      = StringField(required=True)        # full SHA
    message        = StringField(required=True)
    timestamp      = DateTimeField(required=True)      # commit timestamp
    url            = URLField(required=True)           # link to GitHub commit
    author_name    = StringField(required=True)        # commit.author.name
    author_email   = StringField(required=True)        # commit.author.email

class PushEvent(Document):
    """
    A top‐level document for each GitHub 'push' event.
    """
    repo_name      = StringField(required=True)       
    pusher_name    = StringField(required=True)       # e.g. pusher.name
    pusher_email   = StringField(required=True)       # pusher.email
    pushed_at      = DateTimeField(default=datetime.utcnow)  # our own record‐time
    commits        = ListField(EmbeddedDocumentField(CommitEmbedded))
    branch         = StringField(required=True)       # e.g. "refs/heads/main" → we can store just "main"
    raw_payload    = StringField()                    # (optional) store the full JSON string
