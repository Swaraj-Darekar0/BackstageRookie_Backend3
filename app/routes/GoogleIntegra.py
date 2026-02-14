import os
from flask import Blueprint, session, redirect, request, jsonify, url_for
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from flask_cors import CORS


google_auth_bp = Blueprint("google_auth", __name__)
if os.path.exists("/etc/secrets/client_secret.json"):
    CLIENT_SECRETS_FILE = "/etc/secrets/client_secret.json"
else:
    CLIENT_SECRETS_FILE = os.path.join(os.path.dirname(__file__), "client_secret.json")


SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/generative-language.peruserquota",
    "https://www.googleapis.com/auth/generative-language.retriever"
]

@google_auth_bp.route("/api/auth/google/login")
def google_login():
    # Force clear any existing session to ensure a fresh login
    session.clear()
    
    redirect_uri = url_for('google_auth.google_callback', _external=True)

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=redirect_uri
    )

    auth_url, state = flow.authorization_url(
        prompt="consent",
        access_type='offline',
        include_granted_scopes='false'
    )
    session["state"] = state

    return redirect(auth_url)


@google_auth_bp.route("/api/auth/google/callback")
def google_callback():
    redirect_uri = url_for('google_auth.google_callback', _external=True)

    # --- BRAVE FIX STARTS HERE ---
    # We check if 'state' exists in the session before trying to use it.
    if "state" in session:
        # Standard Browser: We have the cookie, so we enforce strict security
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=session["state"], 
            redirect_uri=redirect_uri
        )
    else:
        # Brave/Privacy Browser: Cookie was blocked/lost.
        # We Initialize Flow WITHOUT 'state' to skip the mismatch error.
        print("Warning: State cookie missing (likely Brave). Skipping state verification.")
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
    # --- BRAVE FIX ENDS HERE ---

    try:
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials

        if not creds.id_token:
            print("Google OAuth callback failed: No ID token received.")
            session.clear()
            return redirect("https://backstage-rookie.vercel.app/login?error=no_id_token")

        # Store token in session (for standard browsers that support it)
        session["google_access_token"] = creds.token
        session["google_id_token"] = creds.id_token
        if creds.refresh_token:
            session["google_refresh_token"] = creds.refresh_token

        # Redirect to frontend with the URL Fragment (This is your existing correct code)
        frontend_url = f"https://backstage-rookie.vercel.app/oauth/callback#access_token={creds.token}"
        return redirect(frontend_url)

    except Exception as e:
        print(f"Google OAuth callback failed: {e}")
        session.clear()
        return redirect("https://backstage-rookie.vercel.app/login?error=auth_cancelled")

@google_auth_bp.route("/api/auth/google/session", methods=["GET"])
def get_google_session():
    token = session.get("google_access_token")

    if not token:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "access_token": token
    })


