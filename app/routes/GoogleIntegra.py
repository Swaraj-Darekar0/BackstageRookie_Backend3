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
    "https://www.googleapis.com/auth/generative-language.retriever",
    "https://www.googleapis.com/auth/drive.readonly" 
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
        include_granted_scopes='true'
    )
    session["state"] = state

    return redirect(auth_url)


@google_auth_bp.route("/api/auth/google/callback")
def google_callback():
    redirect_uri = url_for('google_auth.google_callback', _external=True)
    
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=session["state"],
        redirect_uri=redirect_uri
    )

    try:
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials

        if not creds.id_token:
            # Fallback for unexpected missing ID token if fetch_token didn't error
            session.clear()
            return redirect("https://backstage-rookie-frontend.vercel.app/login?error=no_id_token")

        # Store token in session
        session["google_access_token"] = creds.token
        session["google_id_token"] = creds.id_token
        if creds.refresh_token:
            session["google_refresh_token"] = creds.refresh_token


        #  IMPORTANT: redirect to FRONTEND
        return redirect("https://backstage-rookie-frontend.vercel.app/oauth/callback")

    except Exception as e:
        # Handles user cancellation, invalid state, or any other token exchange error
        print(f"Google OAuth callback failed: {e}")
        session.clear() # Clear any potentially incomplete or invalid session data
        return redirect("https://backstage-rookie-frontend.vercel.app/login?error=auth_cancelled")

@google_auth_bp.route("/api/auth/google/session", methods=["GET"])
def get_google_session():
    token = session.get("google_access_token")

    if not token:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "access_token": token
    })


