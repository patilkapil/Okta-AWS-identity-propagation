"""Tiny Flask app: log in with Okta, then read a file from S3 *as that Okta user*.

Run:  python app.py   then open http://localhost:5000
"""

import base64
import hashlib
import html
import json
import os
import secrets
from urllib.parse import urlencode

import requests
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from flask import Flask, redirect, request, session

load_dotenv()

import tip  # noqa: E402  (reads env vars, so import after load_dotenv)

OKTA_ISSUER = os.environ["OKTA_ISSUER"].rstrip("/")
OKTA_CLIENT_ID = os.environ["OKTA_CLIENT_ID"]
OKTA_CLIENT_SECRET = os.environ["OKTA_CLIENT_SECRET"]
REDIRECT_URI = os.environ.get("OKTA_REDIRECT_URI", "http://localhost:5000/callback")
BUCKET = os.environ["S3_BUCKET"]
DEFAULT_KEY = os.environ.get("S3_KEY", "demo/hello.txt")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

_oidc_config = None


def oidc_config():
    global _oidc_config
    if _oidc_config is None:
        _oidc_config = requests.get(f"{OKTA_ISSUER}/.well-known/openid-configuration", timeout=10).json()
    return _oidc_config


def page(body):
    return f"""<!doctype html><html><head><title>Okta → S3 demo</title>
<style>body{{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;line-height:1.5}}
pre{{background:#f4f4f4;padding:12px;overflow-x:auto;border-radius:6px}}
.err{{color:#b00020}} input{{width:60%}}
.jwt-raw{{word-break:break-all;font-family:monospace;font-size:13px;line-height:1.8}}
.jwt-header{{color:#fb015b}}.jwt-payload{{color:#d63aff}}.jwt-sig{{color:#00b9f1}}
.jwt-section{{margin-top:16px}}</style></head><body>
<h2>Okta → IAM Identity Center → S3 Access Grants</h2>{body}</body></html>"""


def jwt_view(token, title):
    parts = token.split(".")
    if len(parts) != 3:
        return '<p class="err">Invalid JWT</p>'
    header = tip.decode_jwt_part(parts[0])
    payload = tip.decode_jwt_part(parts[1])
    return f"""
<h3>{html.escape(title)}</h3>
<div class="jwt-raw">
  <span class="jwt-header">{html.escape(parts[0])}</span>.<span
        class="jwt-payload">{html.escape(parts[1])}</span>.<span
        class="jwt-sig">{html.escape(parts[2])}</span>
</div>
<div class="jwt-section">
  <b>Header</b>
  <pre>{html.escape(json.dumps(header, indent=2))}</pre>
</div>
<div class="jwt-section">
  <b>Payload</b>
  <pre>{html.escape(json.dumps(payload, indent=2))}</pre>
</div>
<div class="jwt-section">
  <b>Signature</b>
  <pre>{html.escape(parts[2])}</pre>
</div>"""


@app.route("/")
def index():
    user = session.get("user")
    if not user:
        return page('<p>Not signed in.</p><p><a href="/login">Sign in with Okta</a></p>')
    return page(f"""
<p>Signed in as <b>{html.escape(user.get("email") or user["sub"])}</b> · <a href="/logout">Sign out</a></p>
<form action="/file">
  <label>s3://{html.escape(BUCKET)}/ <input name="key" value="{html.escape(DEFAULT_KEY)}"></label>
  <button>Fetch file as me</button>
</form>""")


@app.route("/login")
def login():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    session["pkce_verifier"] = verifier
    session["state"] = secrets.token_urlsafe(16)
    params = {
        "client_id": OKTA_CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": REDIRECT_URI,
        "state": session["state"],
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return redirect(f"{oidc_config()['authorization_endpoint']}?{urlencode(params)}")


@app.route("/callback")
def callback():
    if request.args.get("error"):
        return page(f'<p class="err">Okta error: {html.escape(request.args.get("error_description", request.args["error"]))}</p>')
    if request.args.get("state") != session.pop("state", None):
        return page('<p class="err">State mismatch. <a href="/login">Try again</a></p>'), 400

    tokens = requests.post(
        oidc_config()["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": request.args["code"],
            "redirect_uri": REDIRECT_URI,
            "code_verifier": session.pop("pkce_verifier", ""),
        },
        auth=(OKTA_CLIENT_ID, OKTA_CLIENT_SECRET),
        timeout=10,
    ).json()
    if "id_token" not in tokens:
        return page(f'<p class="err">Token request failed:</p><pre>{html.escape(json.dumps(tokens, indent=2))}</pre>'), 400

    # The ID token's `aud` is OKTA_CLIENT_ID, which is exactly what the
    # Identity Center application is configured to accept.
    session["id_token"] = tokens["id_token"]
    session["user"] = tip.decode_jwt(tokens["id_token"])
    return redirect("/")


@app.route("/file")
def file():
    if "id_token" not in session:
        return redirect("/login")
    key = request.args.get("key", DEFAULT_KEY)
    try:
        data, trace = tip.fetch_file_as_user(session["id_token"], BUCKET, key)
    except ClientError as e:
        err = e.response["Error"]
        return page(f"""<p class="err"><b>{html.escape(err.get("Code", ""))}</b>: {html.escape(err.get("Message", ""))}</p>
<p>Failed calling <code>{html.escape(e.operation_name)}</code>. If this is GetDataAccess → AccessDenied,
this user simply has no S3 Access Grant covering <code>{html.escape(key)}</code>, which is the point of the demo.</p>
<p><a href="/">Back</a></p>""")

    return page(f"""
<p><a href="/">Back</a></p>
<h3>s3://{html.escape(BUCKET)}/{html.escape(key)}</h3>
<pre>{html.escape(data.decode("utf-8", errors="replace"))}</pre>
<h3>How the identity got here</h3>
<pre>{html.escape(json.dumps(trace, indent=2, default=str))}</pre>
{jwt_view(session["id_token"], "ID Token (Okta)")}""")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(port=5000, debug=True)
