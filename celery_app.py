
from dotenv import load_dotenv
  # Load environment variables from .env file
import os
from celery import Celery
load_dotenv()
def make_celery(app_name=__name__):
    redis_url = os.getenv('REDIS_URL')
    
    celery_app = Celery(
        app_name,
        broker=redis_url,
        backend=redis_url,
        include=['app.tasks']
    )
    celery_app.conf.update(
        # --- REDUCE HEARTBEAT FREQUENCY ---
        # Disable worker events entirely (This stops the PUBLISH in your logs)
        worker_send_task_events=False, 
        task_send_sent_event=False,
        worker_event_heartbeat=15.0,
        # If you still want heartbeats but slower, set these:
        # Check in every 5 minutes instead of every few seconds
        broker_heartbeat=30, 
        
        # --- OPTIMIZE POLLING ---
        result_expires=10800,
        broker_transport_options={
            'visibility_timeout': 3600,
            'polling_interval': 30.0, # Check for new tasks once a minute
        },
        
        broker_pool_limit=None, # Helps stabilize connection reuse
        redis_backend_use_ssl={'ssl_cert_reqs': 'none'},
        task_ignore_result=True # Ignore results by default to save more commands
    )
    
    return celery_app
# Create the Celery instance WITHOUT creating a Flask app instance here
celery = make_celery()

# Keep the Task class definition, but don't use flask_app here yet.
# We will override this in __init__.py where the app is actually created.