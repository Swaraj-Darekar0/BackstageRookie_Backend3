from flask import Flask
from flask_cors import CORS
import os
import sys

# Import the celery instance created in celery_app.py
from celery_app import celery

def create_app():
    app = Flask(__name__)

    # Project path setup
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    app.config['PULLED_CODE_DIR'] = os.path.join(project_root, 'PulledCode_temp')
    app.config['DATA_DIR'] = os.path.join(project_root, 'data')
    app.config['TEMPLATES_DIR'] = os.path.join(project_root, 'templates')

    CORS(app, supports_credentials=True, origins=["https://backstage-rookie-frontend.vercel.app","https://backstage-rookie-frontend.vercel.app"])
    
    # --- Celery Integration ---
    # Update Celery with Flask's configuration
    celery.conf.update(app.config)

    # Wrap Celery tasks in the Flask app context
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    app.celery = celery 
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.config['SESSION_COOKIE_SAMESITE'] = 'None' #
    app.config['SESSION_COOKIE_SECURE'] = True
    #  # Set to True in production with HTTPS
    app.config['SESSION_COOKIE_DOMAIN'] = 'backstagerookie-backend3.onrender.com' # Set to your backend domain
    app.config['SESSION_COOKIE_HTTPONLY'] = True

    # Register blueprints
    from app.routes.GoogleIntegra import google_auth_bp
    from app.routes.main import main_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(google_auth_bp)
     
    return app