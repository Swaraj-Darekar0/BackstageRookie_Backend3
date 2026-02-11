import asyncio
import os
import sys
from flask import Flask

# --- STEP 1: FIX SYSTEM PATH ---
# Find the 'backend' directory (the grandparent of this script)
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_root = os.path.abspath(os.path.join(current_dir, '..', '..'))
sys.path.insert(0, backend_root)

# Now we can import the service
from app.services.report_service_two import ReportServiceTwo

def create_test_app():
    """Sets up a minimal Flask app to provide the necessary config context."""
    app = Flask(__name__)
    
    base_dir = os.path.abspath(os.path.dirname(__file__))

    # DATA_DIR -> backend\data (two levels up from services)
    app.config['DATA_DIR'] = os.path.abspath(os.path.join(base_dir, '..', '..', 'data'))

    # TEMPLATES_DIR -> backend\templates (updated to match actual file location)
    app.config['TEMPLATES_DIR'] = os.path.abspath(os.path.join(base_dir, '..', '..', 'templates'))
    
    return app

async def run_test():
    app = create_test_app()
    
    # Use the app context so 'current_app' is available inside the service
    with app.app_context():
        service = ReportServiceTwo()
        
        # The specific scan ID provided
        test_scan_id = "592bf34f-5647-44b2-ad14-019dcabd8804"
        
        try:
            print(f"--- Starting PDF Generation for {test_scan_id} ---")
            print(f"Data directory: {app.config['DATA_DIR']}")
            
            pdf_path = await service.generate_pdf_report(test_scan_id)
            
            print(f"--- Success! ---")
            print(f"Report saved at: {pdf_path}")
            
        except Exception as e:
            print(f"--- Test Failed ---")
            # Using __repr__ gives more detail on the error type
            print(f"Error: {repr(e)}")

if __name__ == "__main__":
    asyncio.run(run_test())