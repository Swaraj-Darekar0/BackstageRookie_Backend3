
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
        include=['app.tasks']  # NEW: Automatically discover tasks
    )
    celery_app.conf.update(
        # Increase the time a worker waits for a message from 1s to 5s or 10s
        # This directly reduces BRPOP frequency
        result_expires=10800,
        broker_transport_options={
            'visibility_timeout': 3600,
            'polling_interval': 15.0  # Check every 10 seconds instead of 1
        },
        
        # Reduce connection overhead by keeping connections open
        broker_pool_limit=2, 
        redis_backend_use_ssl={'ssl_cert_reqs': 'none'},# Keep your SSL setting
        task_ignore_result=False 
      )
    
    return celery_app

# Create the Celery instance WITHOUT creating a Flask app instance here
celery = make_celery()

# Keep the Task class definition, but don't use flask_app here yet.
# We will override this in __init__.py where the app is actually created.