import os
import shutil
import stat
import json
import uuid
from datetime import datetime
from celery_app import celery
from flask import Flask, current_app
from app.services.github_service import GitHubService
from app.services.analysis_service import AnalysisService
from app.services.report_service import ReportService
from app.services.django_info_service import extract_django_endpoints
from app.services.flaskFastApi_info_service import extract_flask_fastapi_endpoints
from app.services.report_service_two import ReportServiceTwo # NEW: For generate_report_task
import asyncio # NEW: For generate_report_task
from supabase import create_client, Client
from app.tasksLLM.utils import load_scan_results_helper, generate_br_advice_with_gemini # NEW: Helper functions
from google.oauth2.credentials import Credentials
import google.generativeai as genai



SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

@celery.task(bind=True)
def run_analysis_task(self, scan_id: str, github_url: str, sector_hint: str, framework_hint: str, plan: str, user_token: str):
    from app import create_app
    app = create_app()  
    with app.app_context():
        self.update_state(state='PROGRESS', meta={'message': 'Starting Analysis...'})
        repo_name = github_url.split('/')[-1].replace('.git', '')
        repo_path = os.path.join(app.config['PULLED_CODE_DIR'], scan_id, repo_name)
        framework_analysis_results = None  # Initialize here

        try:
            print(f"[Task:{self.request.id}] Starting Analysis for scan {scan_id}")
            self.update_state(state='PROGRESS', meta={'message': f'Started Clonning...{repo_name}'})
            # 1. Update GitHub Service: Pass user_token
            github_service = GitHubService()
            github_service.clone_repository(github_url, repo_path, user_token)

            self.update_state(state='PROGRESS', meta={'message': 'Running Vulnerability Analysis...'})
            # 2. Update Analysis Service: Pass user_token
            analysis_service = AnalysisService(plan=plan)
            # We add user_token here because AnalysisService likely calls Gemini for vulnerability scanning
            scan_results = analysis_service.analyze_codebase(repo_path, sector_hint, scan_id, user_token)
            
            if framework_hint:
                print(f"[Task:{self.request.id}] Starting framework analysis: {framework_hint}")
                self.update_state(state='PROGRESS', meta={'message': f'Running Framework/Endpoint Analysis ...'})
                try:
                    # These already take user_token, which is good!
                    if framework_hint == 'django':
                        framework_analysis_results = extract_django_endpoints(
                            repo_path=repo_path, 
                            user_token=user_token, 
                            sector=sector_hint
                        )
                    elif framework_hint in ['flask', 'fastapi']:
                        framework_analysis_results = extract_flask_fastapi_endpoints(
                            repo_path=repo_path, 
                            user_token=user_token, 
                            sector=sector_hint
                        )
                    
                    if framework_analysis_results:
                        results_path = os.path.join(app.config['DATA_DIR'], "scanned_results", f"{scan_id}.json")
                        if os.path.exists(results_path):
                            with open(results_path, 'r+') as f:
                                saved_data = json.load(f)
                                saved_data['framework_analysis'] = framework_analysis_results
                                f.seek(0)
                                json.dump(saved_data, f, indent=2)
                                f.truncate()
                            print(f"[/api/analyze] Successfully merged framework analysis into {scan_id}.json")
                            self.update_state(state='PROGRESS', meta={'message': 'Analysis successfully completed'})
                except Exception as fw_e:
                    print(f"[Task:{self.request.id}] Framework analysis failed: {str(fw_e)}")

            return {
                'status': 'success',
                'scan_id': scan_id,
                'plan_used': plan,
                'total_findings': scan_results.get('total_findings', 0),
                'message': 'Analysis complete!',
                'findings': scan_results.get('findings', []),
                'framework_analysis': framework_analysis_results,
                'ExecutiveSummary': scan_results.get('executive_summary'),
                'Methodology': scan_results.get('methodology')
            }
        
        except Exception as e:
            print(f"[Task:{self.request.id}] ERROR: {str(e)}")
            raise
        finally:
            parent_dir = os.path.dirname(repo_path)
            if os.path.exists(parent_dir):
                shutil.rmtree(parent_dir, onerror=_remove_readonly_onerror)

@celery.task(bind=True)
def generate_report_task(self, scan_id: str, report_type: str, user_token: str, model_name: str, user_name: str, user_email: str):
    from app import create_app
    app = create_app()
    
    with app.app_context():
        pdf_report_path = None  # Initialize here
        docx_report_path = None # Initialize here
        try:
            print(f"[Task:{self.request.id}] Report generation for Scan ID: {scan_id}")
            self.update_state(state='PROGRESS', meta={'message': f'Generating report for Scan ID: {scan_id}'})
            # 1. Helper functions: Passing user_token
            scan_results = load_scan_results_helper(scan_id)
            br_advice = generate_br_advice_with_gemini(scan_results, user_token, model_name)
            
            scan_results['BRadvice'] = br_advice
            data_dir = current_app.config['DATA_DIR']
            results_path = os.path.join(data_dir, 'scanned_results', f'{scan_id}.json')
            with open(results_path, 'w', encoding='utf-8') as f:
                json.dump(scan_results, f, indent=2)
            print(f"[/api/generate-report] Enriched scan results saved to {results_path}")
            self.update_state(state='PROGRESS', meta={'message': ' Enriched Scan results saved.'})
            # 2. ReportServiceTwo (PDF): Passing user_token if it needs to fetch images or extra data
            
            print(f"[Task:{self.request.id}] Generating PDF locally...")
            report_service_two = ReportServiceTwo()
            pdf_report_path = asyncio.run(report_service_two.generate_pdf_report(
                    scan_id=scan_id, 
                    user_name=user_name, 
                    user_email=user_email,
                    user_token=user_token
                ))
                
                # 4. NEW: Upload to Supabase Storage
            filename = os.path.basename(pdf_report_path)
            print(f"[/api/generate-report] Uploading {filename} to Supabase Storage...")
                
            with open(pdf_report_path, 'rb') as f:
                    # "reports" is the bucket name you must create in Supabase Dashboard
                supabase.storage.from_("reports").upload(
                    path=filename,
                    file=f,
                    file_options={"content-type": "application/pdf", "x-upsert": "true"}
                )

                # 5. Clean up the local worker file to save space
            if os.path.exists(pdf_report_path):
                os.remove(pdf_report_path)

            return {
                'status': 'success',
                'pdf_filename': filename, # We return the filename so main.py knows what to look for
                'message': 'Reports generated and uploaded successfully.'
            }

        except Exception as e:
            print(f"[Task:{self.request.id}] ERROR: {str(e)}")
            raise

@celery.task(ignore_result=True)
def cleanup_scan_data(scan_id):
    """
    Deletes JSON results and PDF reports associated with a scan_id.
    """
    from flask import current_app
    from app import create_app
    import os

    # We need an app context to access config['DATA_DIR']
    app = create_app()
    with app.app_context():
        data_dir = app.config['DATA_DIR']
        
        # Define paths to clean up
        files_to_remove = [
            os.path.join(data_dir, 'scanned_results', f'{scan_id}.json'),
            os.path.join(data_dir, 'generated_reports', f'report_{scan_id}.pdf'),
            # Add docx or other formats if you use them
            os.path.join(data_dir, 'generated_reports', f'report_{scan_id}_regulatory.pdf'),
            os.path.join(data_dir, 'generated_reports', f'report_{scan_id}_technical.pdf')
        ]

        print(f"[Cleanup] Starting cleanup for Scan ID: {scan_id}")
        
        for file_path in files_to_remove:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"[Cleanup] Deleted: {file_path}")
            except Exception as e:
                print(f"[Cleanup] Error deleting {file_path}: {e}")

    try:
        filenames = [
            f"report_{scan_id}.pdf",
            f"report_{scan_id}_technical.pdf"
        ]
        # Remove from bucket
        supabase.storage.from_("reports").remove(filenames)
        print(f"[Cleanup] Removed reports from Supabase for {scan_id}")
    except Exception as e:
        print(f"[Cleanup] Supabase cleanup error: {e}")          