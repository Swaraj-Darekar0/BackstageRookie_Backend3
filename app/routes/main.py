import os
import psycopg2
import json
import uuid
import shutil
import stat
import asyncio # New import for async operations
import re
from dotenv import load_dotenv
from google.oauth2 import id_token
from google.oauth2.credentials import Credentials
import google.generativeai as genai
from google.auth.transport import requests as google_requests
import redis
# Add the new task to your imports
from functools import wraps
from flask import request, jsonify, Blueprint, send_file, session, current_app, url_for
from celery_app import celery # NEW: Import the Celery app instance


from app.tasks import run_analysis_task, generate_report_task,cleanup_scan_data


main_bp = Blueprint('main', __name__)

load_dotenv()
# Global variable to store current plan (in production, use database)
CURRENT_PLAN = 'basic'  # Default plan

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # 1. Check for Bearer token in Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            # For now, simply having the token is enough.
            # You might want to validate it here.
            if 'google_access_token' not in session:
                session['google_access_token'] = token

        # 2. Fallback to checking session
        if "google_access_token" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


@main_bp.route('/healthz')
def health_check():
    """Health check endpoint for Render."""
    return jsonify({"status": "healthy"}), 200


@main_bp.route('/api/change-plan', methods=['POST'])
def change_plan():
    """Change analysis plan configuration"""
    global CURRENT_PLAN
    
    try:
        data = request.get_json()
        new_plan = data.get('plan')
        
        if new_plan not in ['basic', 'full']:
            return jsonify({'status': 'error', 'message': 'Invalid plan'}), 400
        
        # Update global plan
        CURRENT_PLAN = new_plan
        
        print(f"[/api/change-plan] Plan changed to: {new_plan}")
        
        return jsonify({
            'status': 'success',
            'plan': new_plan,
            'message': f'Plan changed to {new_plan}'
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@main_bp.route('/api/auth/logout', methods=['POST'])
def logout():
    """Clears session and deletes generated files."""
    
    # 1. NEW: Trigger immediate cleanup for all scans in this session
    active_scans = session.get('active_scans', [])
    if active_scans:
        print(f"[/api/auth/logout] Triggering cleanup for scans: {active_scans}")
        for scan_id in active_scans:
            # Call the task immediately (delay) instead of waiting for the countdown
            cleanup_scan_data.delay(scan_id)

    # 2. Clear the session
    session.clear()
    return jsonify({"status": "success", "message": "Session cleared and temporary files cleaned up."})


@main_bp.route('/api/get-plan', methods=['GET'])
@login_required
def get_plan():
    """Get current plan"""
    global CURRENT_PLAN
    return jsonify({
        'status': 'success',
        'plan': CURRENT_PLAN
    })


def _remove_readonly_onerror(func, path, _):
    """
    Error handler for `shutil.rmtree`.
    If the error is due to an access error (read-only file), it attempts to
    add write permission and then retries the operation.
    """
    os.chmod(path, stat.S_IWRITE)
    func(path)

redis_url = os.getenv('REDIS_URL')

r = redis.from_url(redis_url, decode_responses=True)
@main_bp.route('/api/analyze', methods=['POST'])
@login_required
def analyze_repository():

    data = request.get_json(force=True, silent=True)
    if not data or not data.get('github_url'):
        return jsonify({"error": "github_url is required"}), 400
    # 1. ATOMIC REDIS CHECK (Do this first to save resources)
    user_email = session.get('user_email', 'anonymous') 
    redis_key = f"scan_limit:{user_email}"

    current_usage = r.incr(redis_key)

    if current_usage == 1:
        r.expire(redis_key, 86400) # 24-hour reset

    if current_usage > 3:
        # If they hit the limit, we MUST decrement so this failed attempt 
        # doesn't keep pushing the counter up indefinitely
        r.decr(redis_key) 
        return jsonify({
            "status": "error",
            "message": "Maximum of 3 attempts reached. Please try again in 24 hours."
        }), 429
    
    # 2. DATA VALIDATION
    data = request.get_json(force=True, silent=True)
    if not data:
        r.decr(redis_key) # Refund attempt for bad payload
        return jsonify({"error": "Invalid JSON payload"}), 400

    github_url = data.get('github_url')
    if not github_url:
        r.decr(redis_key) # Refund attempt for missing URL
        return jsonify({"error": "github_url is required"}), 400

    # ... (Keep your sector/framework/token logic here) ...
    sector_hint = data.get('sector_hint') or 'General Data Privacy'
    framework_hint = data.get('backend_framework', '').lower()
    plan = data.get('plan', CURRENT_PLAN)
    user_token = session.get('google_access_token')

    if not user_token:
        r.decr(redis_key) # Refund attempt for auth error
        return jsonify({"error": "Unauthorized: Google access token missing from session."}), 401
    
    scan_id = str(uuid.uuid4())
    
    # Track active scans for cleanup on logout
    if 'active_scans' not in session:
        session['active_scans'] = []
    session['active_scans'].append(scan_id)
    session.modified = True 

    # 3. DISPATCH TASKS
    cleanup_scan_data.apply_async(args=[scan_id], countdown=3600)
    
    task = run_analysis_task.delay(
        scan_id=scan_id,
        github_url=github_url,
        sector_hint=sector_hint,
        framework_hint=framework_hint,
        plan=plan,
        user_token=user_token
    )
    
    return jsonify({
        'status': 'success',
        'message': 'Analysis started',
        'task_id': task.id,
        'scan_id': scan_id,
        'remaining_tries': max(0, 3 - current_usage) # Corrected reference
    }), 202


@main_bp.route('/api/scan-usage', methods=['GET'])
@login_required
def get_scan_usage():
    user_email = session.get('user_email', 'anonymous')
    val = r.get(f"scan_limit:{user_email}")
    count = int(val) if val else 0
    return jsonify({"remaining": max(0, 3 - count)})

@main_bp.route('/api/scan/status/<task_id>', methods=['GET'])
@login_required
def get_scan_status(task_id):
    task = celery.AsyncResult(task_id)

    response_data = {
        'task_id': task.id,
        'status': task.status,
        'progress_message': '',
        'result': None
    }
    if task.status == 'PROGRESS':
        # This picks up the 'meta' dictionary from update_state
        response_data['progress_message'] = task.info.get('message', '')
    elif task.ready():
        if task.failed():
            response_data['result'] = {'error': str(task.result)}
        else:
            response_data['result'] = task.result
            response_data['progress_message'] = 'Analysis Complete!'

    return jsonify(response_data)

@main_bp.route('/api/generate-report', methods=['POST'])
@login_required
def generate_report():
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        report_type = data.get('report_type') # business, technical, regulatory
        model_name = data.get('model_name', 'models/gemini-2.5-flash-lite') 

        user_token = session.get('google_access_token')
        if not user_token:
            return jsonify({'status': 'error', 'message': 'User token not found in session.'}), 401
        
        # Get user profile info for the report (needed by ReportServiceTwo)
        user_name = "N/A"
        user_email = "N/A"
        if 'google_id_token' in session:
            try:
                id_info = id_token.verify_oauth2_token(session['google_id_token'], google_requests.Request())
                user_name = id_info.get('name', 'N/A')
                user_email = id_info.get('email', 'N/A')
            except ValueError:
                print("[/api/generate-report] Warning: Could not verify ID token. Using default user info for report.")
        else:
            print("[/api/generate-report] Warning: google_id_token not in session. Using default user info for report.")

        # Dispatch the report generation task to Celery
        task = generate_report_task.delay(
            scan_id=scan_id,
            report_type=report_type,
            user_token=user_token,
            model_name=model_name,
            user_name=user_name,
            user_email=user_email
        )
        
        print(f"[/api/generate-report] Dispatched report generation task: {task.id} for Scan ID: {scan_id}")

        return jsonify({
            'status': 'success',
            'message': 'Report generation started.',
            'task_id': task.id
        }), 202 # 202 Accepted
    
    except Exception as e:
        print(f"[/api/generate-report] UNEXPECTED ERROR: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@main_bp.route('/api/report/status/<task_id>', methods=['GET'])
@login_required
def get_report_status(task_id):
    task = celery.AsyncResult(task_id)
    response_data = {
        'task_id': task.id,
        'status': task.status
    }
    
    if task.ready():
        if task.successful():
            result = task.result
            pdf_filename = result.get('pdf_filename')
            pdf_url = url_for('main.download_report', filename=pdf_filename) if pdf_filename else None
            
            # ### NEW: Load scan results to get framework_analysis ###
            framework_analysis_data = None
            scan_id = None
            try:
                # The task arguments are stored in a tuple: (scan_id, report_type, ...)
                if task.args:
                    scan_id = task.args[0]
                    results_path = os.path.join(current_app.config['DATA_DIR'], 'scanned_results', f'{scan_id}.json')
                    if os.path.exists(results_path):
                        with open(results_path, 'r', encoding='utf-8') as f:
                            scan_data = json.load(f)
                            framework_analysis_data = scan_data.get('framework_analysis')
            except Exception as e:
                print(f"[get_report_status] WARNING: Could not load framework_analysis for scan {scan_id}. Error: {e}")
            # ### END NEW ###

            response_data['result'] = {
                'message': result.get('message', 'Reports generated successfully.'),
                'pdf_report_url': pdf_url,
                'framework_analysis': framework_analysis_data # Include framework analysis in the response
            }
        else:
            response_data['result'] = {'error': str(task.result)}
    else:
        response_data['result'] = None # Task not yet complete or pending
        
    return jsonify(response_data)


@main_bp.route('/api/reports/download/<filename>', methods=['GET'])
@login_required
def download_report(filename):
    """
    Allows downloading of generated reports.
    Includes security measures to prevent path traversal.
    """
    reports_dir = os.path.join(current_app.config['DATA_DIR'], 'generated_reports')
    
    # Security: Prevent path traversal
    base = os.path.normpath(reports_dir)
    full_path = os.path.normpath(os.path.join(base, filename))

    if not full_path.startswith(base):
        # Attempted path traversal
        return jsonify({'status': 'error', 'message': 'Invalid filename or attempted path traversal.'}), 400

    if not os.path.exists(full_path):
        return jsonify({'status': 'error', 'message': 'File not found.'}), 404

    try:
        mimetype = None
        if filename.endswith('.pdf'):
            mimetype = 'application/pdf'
        elif filename.endswith('.docx'):
            mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        
        return send_file(full_path, as_attachment=True, download_name=filename, mimetype=mimetype)
    except Exception as e:
        print(f"[/api/reports/download/{filename}] ERROR: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Could not serve file.'}), 500

@main_bp.route('/api/auth/me', methods=['GET'])
@login_required
def get_user_profile():
    """Get user profile from ID token and save/update to Supabase."""
    if 'google_id_token' not in session:
        return jsonify({"error": "ID token not found in session"}), 401
    
    id_token_str = session['google_id_token']
    try:
        id_info = id_token.verify_oauth2_token(id_token_str, google_requests.Request())
        user_email = id_info.get('email')
        session['user_email'] = user_email 
        session.modified = True
        user_profile = {
            'name': id_info.get('name'),
            'email': id_info.get('email'),
            'picture': id_info.get('picture')
        }

        # --- NEW: Save user to Supabase ---
        try:
            db_url = os.getenv("SUPABASE_DB_URL")
            if db_url:
                # Normalize common misconfigurations:
                # - remove surrounding quotes
                # - handle values like "DATABASE_URL=postgresql://..." by extracting after '='
                db_url_clean = db_url.strip().strip('"').strip("'")
                if db_url_clean.upper().startswith('DATABASE_URL='):
                    db_url_clean = db_url_clean.split('=', 1)[1]

                try:
                    conn = psycopg2.connect(db_url_clean)
                    cur = conn.cursor()

                    # Use UPSERT logic: Insert a new user, or update their name if the email already exists.
                    cur.execute(
                        """
                        INSERT INTO users (email, name)
                        VALUES (%s, %s)
                        ON CONFLICT (email)
                        DO UPDATE SET name = EXCLUDED.name;
                        """,
                        (user_profile['email'], user_profile['name'])
                    )

                    conn.commit()
                    cur.close()
                    conn.close()
                    print(f"[/api/auth/me] Successfully saved/updated user {user_profile['email']} to database.")
                except Exception as db_error:
                    # Log the error but don't fail the login request
                    print(f"[/api/auth/me] ERROR: Could not save user to database. Sanitized SUPABASE_DB_URL: {db_url_clean}. Error: {str(db_error)}")
            else:
                print("[/api/auth/me] WARNING: SUPABASE_DB_URL environment variable not set. Skipping database operation.")

        except Exception as db_error:
            # Catch any unexpected exceptions during env read/sanitize
            print(f"[/api/auth/me] ERROR: Unexpected error when handling SUPABASE_DB_URL: {str(db_error)}")
        # --- END NEW ---

        return jsonify(user_profile)
    except ValueError as e:
        return jsonify({"error": "Invalid ID token", "message": str(e)}), 401


@main_bp.route('/api/models', methods=['GET'])
@login_required
def list_models():
    """List available Gemini models for the authenticated user."""
    user_token = session.get('google_access_token')
    if not user_token:
        return jsonify({'status': 'error', 'message': 'User token not found in session.'}), 401

    api_key_env = os.environ.pop('GOOGLE_API_KEY', None)
    gemini_key_env = os.environ.pop('GEMINI_API_KEY', None)

    try:
        # Correctly create a Credentials object from the user's access token
        user_credentials = Credentials(token=user_token)
        genai.configure(credentials=user_credentials, api_key=None)
        
        models_list = []
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                models_list.append({
                    'name': m.name,
                    'display_name': m.display_name,
                    'description': m.description,
                })
        return jsonify(models_list)
    except Exception as e:
        print(f"[/api/models] ERROR: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to list models.'}), 500
    finally:
        if api_key_env:
            os.environ['GOOGLE_API_KEY'] = api_key_env
        if gemini_key_env:
            os.environ['GEMINI_API_KEY'] = gemini_key_env