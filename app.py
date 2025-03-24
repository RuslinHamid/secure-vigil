from flask import Flask, request, render_template, redirect, url_for, send_file, flash, session, jsonify, send_from_directory
from flask_mail import Mail, Message
from flask_session import Session
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import os
import re
import time
import smtplib
import logging
import tempfile
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from config.logging_config import setup_logging
from datetime import datetime
import json
from dotenv import load_dotenv

from vulnerabilities.injection.code_injection_vulnerabilities import find_code_injection_vulnerabilities
from vulnerabilities.sqli.sql_injection_vulnerabilities import find_sql_injection_vulnerabilities
from vulnerabilities.lfi.lfi_vulnerabilities import find_lfi_vulnerabilities
from vulnerabilities.rfi.rfi_vulnerabilities import find_rfi_vulnerabilities
from vulnerabilities.xss.xss_vulnerabilities import find_xss_vulnerabilities
from vulnerabilities.command_injection.command_injection_vulnerabilities import find_command_injection_vulnerabilities
from vulnerabilities.crypto.crypto_vulnerabilities import find_crypto_vulnerabilities
from vulnerabilities.Redirects_and_Forwards.redirect_vulnerabilities import find_redirect_vulnerabilities
from vulnerabilities.shell.shell_vulnerabilities import find_shell_vulnerabilities
from vulnerabilities.upload.upload_vulnerabilities import find_upload_vulnerabilities
from vulnerabilities.c_lang.vulnerabilities import find_c_vulnerabilities
from vulnerabilities.javascript.vulnerabilities import find_javascript_vulnerabilities
from vulnerabilities.java.vulnerabilities import find_java_vulnerabilities
from vulnerabilities.python.vulnerabilities import find_python_vulnerabilities
from security_verification import SecurityVerifier
from utils.file_handler import read_file_with_encoding, get_file_language

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(tempfile.gettempdir(), 'flask_session')
Session(app)

# Disable auto-reload for temp files
app.config['DEBUG'] = True
extra_files = []
def should_reload(filename):
    if filename.startswith(os.path.join(tempfile.gettempdir(), 'temp_')):
        return False
    if filename.startswith(os.path.join(UPLOAD_FOLDER, 'temp_')):
        return False
    return True
app.jinja_env.auto_reload = True
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Load environment variables
load_dotenv()

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.sendgrid.net'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'apikey'
app.config['MAIL_PASSWORD'] = os.getenv('SENDGRID_API_KEY')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

# Ensure the uploads directory exists
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize rate limiter
app.wsgi_app = ProxyFix(app.wsgi_app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Setup logging
setup_logging()
logger = logging.getLogger('secure_vigil')

# Add this with other app configurations
SECURITY_REPORTS_DIR = os.path.join(app.static_folder, 'security_reports')
os.makedirs(SECURITY_REPORTS_DIR, exist_ok=True)

# Initialize security verifier with the reports directory
security_verifier = SecurityVerifier(report_dir=SECURITY_REPORTS_DIR)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/result')
def result():
    file_path = request.args.get('file_path')
    if not file_path:
        flash('No file path provided.')
        return redirect(url_for('index'))
    
    if 'analysis_results' not in session:
        flash('No analysis results found.')
        return redirect(url_for('index'))
    
    results = session.get('analysis_results', {})
    
    # Check if all required keys are present
    required_keys = [
        'file_path', 
        'vulnerabilities', 
        'mitigations', 
        'vulnerability_summary', 
        'vulnerability_types', 
        'vulnerability_counts', 
        'pdf_path'
    ]
    
    # If any required key is missing, reanalyze the file
    if not all(key in results for key in required_keys):
        try:
            with open(file_path, 'r') as f:
                code = f.read()
            
            vulnerabilities = find_vulnerabilities(code)
            mitigations = generate_mitigations(vulnerabilities)
            vulnerability_types = [v['type'] for v in vulnerabilities]
            vulnerability_summary = {v: vulnerability_types.count(v) for v in set(vulnerability_types)}
            vulnerability_counts = [vulnerability_types.count(v) for v in set(vulnerability_types)]
            pdf_path = generate_pdf(file_path, vulnerabilities, vulnerability_summary, mitigations)
            
            results = {
                'file_path': file_path,
                'vulnerabilities': vulnerabilities,
                'mitigations': mitigations,
                'vulnerability_summary': vulnerability_summary,
                'vulnerability_types': list(set(vulnerability_types)),
                'vulnerability_counts': vulnerability_counts,
                'pdf_path': pdf_path
            }
            
            session['analysis_results'] = results
        except Exception as e:
            flash(f'Error analyzing file: {str(e)}')
            return redirect(url_for('index'))
    
    return render_template(
        'result.html',
        file_path=results['file_path'],
        vulnerabilities=results['vulnerabilities'],
        mitigations=results['mitigations'],
        vulnerability_summary=results['vulnerability_summary'],
        vulnerability_types=results['vulnerability_types'],
        vulnerability_counts=results['vulnerability_counts'],
        pdf_path=results['pdf_path']
    )

def generate_pdf(file_path, vulnerabilities, vulnerability_summary, mitigations):
    pdf_path = file_path.replace('.php', '.pdf')
    c = canvas.Canvas(pdf_path, pagesize=letter)

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, "Vulnerability Analysis Report")
    c.setFont("Helvetica", 12)
    c.drawString(100, 730, f"File Analyzed: {os.path.basename(file_path)}")
    c.drawString(100, 710, f"Total Vulnerabilities: {len(vulnerabilities)}")
    c.line(100, 705, 500, 705)  # Horizontal line

    # Add Summary
    y = 680
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y, "Vulnerability Summary:")
    y -= 20
    c.setFont("Helvetica", 10)
    for vtype, count in vulnerability_summary.items():
        c.drawString(120, y, f"{vtype}: {count}")
        y -= 20

    # Add Detailed Vulnerabilities
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y - 10, "Detailed Vulnerabilities:")
    y -= 30
    c.setFont("Helvetica", 10)

    for vulnerability in vulnerabilities:
        if y < 50:  # Add new page if space is insufficient
            c.showPage()
            c.setFont("Helvetica", 10)
            y = 750

        # Type is required
        c.drawString(120, y, f"Type: {vulnerability['type']}")
        y -= 15

        # Optional fields
        if 'pattern' in vulnerability:
            c.drawString(120, y, f"Pattern: {vulnerability['pattern']}")
            y -= 15
            
        if 'line_number' in vulnerability:
            c.drawString(120, y, f"Line: {vulnerability['line_number']}")
            y -= 15
            
        if 'description' in vulnerability:
            c.drawString(120, y, f"Description: {vulnerability['description']}")
            y -= 15
            
        if 'severity' in vulnerability:
            c.drawString(120, y, f"Severity: {vulnerability['severity']}")
            y -= 15
            
        if 'mitigation' in vulnerability:
            c.drawString(120, y, f"Mitigation: {vulnerability['mitigation']}")
            y -= 15
            
        # Add extra spacing between vulnerabilities
        y -= 15

    # Add Mitigations
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y - 10, "Mitigations:")
    y -= 30
    c.setFont("Helvetica", 10)

    for vtype, mitigation in mitigations.items():
        if y < 50:  # Add new page if space is insufficient
            c.showPage()
            c.setFont("Helvetica", 10)
            y = 750

        c.drawString(120, y, f"Type: {vtype}")
        y -= 15
        # Split mitigation text into lines to avoid overflow
        for line in mitigation.split('\n'):
            if y < 50:  # Check if we need a new page
                c.showPage()
                c.setFont("Helvetica", 10)
                y = 750
            c.drawString(140, y, line[:80])  # Limit line length to avoid overflow
            y -= 15

    c.save()
    return pdf_path

def send_email(recipient, subject, body, attachment):
    msg = Message(subject, sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[recipient])
    msg.body = body
    with app.open_resource(attachment) as fp:
        msg.attach(os.path.basename(attachment), "application/pdf", fp.read())
    try:
        mail.send(msg)
    except smtplib.SMTPException as e:
        logging.error(f"Failed to send email: {e}")
        flash(f'Failed to send email: {str(e)}')

@app.route('/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze_code():
    try:
        data = request.json
        if not data:
            logger.error("No JSON data received in request")
            return jsonify({'error': 'No data provided'}), 400
            
        code = data.get('code')
        language = data.get('language')
        
        logger.info(f"Received analysis request for language: {language}")
        
        if not code:
            logger.error("No code provided in request")
            return jsonify({'error': 'No code provided'}), 400
            
        if not language:
            logger.error("No language specified in request")
            return jsonify({'error': 'No language specified'}), 400
        
        # Create a temporary file for the code
        temp_file = os.path.join(UPLOAD_FOLDER, f'temp_{int(time.time())}.{language}')
        with open(temp_file, 'w') as f:
            f.write(code)
        
        logger.info(f"Analyzing code for vulnerabilities...")
        # Analyze the code with language-specific checks
        vulnerabilities = find_vulnerabilities(code, language)
        
        if vulnerabilities is None:
            logger.error("Vulnerability analysis returned None")
            return jsonify({'error': 'Error during vulnerability analysis'}), 500
            
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
        
        # Generate mitigations
        mitigations = generate_mitigations(vulnerabilities)
        
        # Count vulnerabilities
        vulnerability_types = [v['type'] for v in vulnerabilities]
        vulnerability_summary = {v: vulnerability_types.count(v) for v in set(vulnerability_types)}
        vulnerability_counts = [vulnerability_types.count(v) for v in set(vulnerability_types)]
        
        # Generate PDF report
        pdf_path = generate_pdf(temp_file, vulnerabilities, vulnerability_summary, mitigations)
        
        # Store results in session for the result page
        session['analysis_results'] = {
            'file_path': temp_file,
            'vulnerabilities': vulnerabilities,
            'vulnerability_summary': vulnerability_summary,
            'vulnerability_types': list(set(vulnerability_types)),
            'vulnerability_counts': vulnerability_counts,
            'mitigations': mitigations,
            'pdf_path': pdf_path
        }
        
        logger.info("Analysis completed successfully")
        return jsonify({'redirect': url_for('result', file_path=temp_file)})
        
    except Exception as e:
        logger.error(f"Error in analyze_code: {str(e)}", exc_info=True)
        return jsonify({'error': f'Error analyzing code: {str(e)}'}), 500

@app.route('/upload', methods=['POST'])
@limiter.limit("5 per minute")
def upload_file():
    try:
        logger.info("Starting file upload process")
        
        # Check if the post request has the file part
        if 'file' not in request.files:
            logger.warning("No file part in request")
            return jsonify({'error': 'No file selected'}), 400
            
        file = request.files['file']
        
        # If user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            logger.warning("Empty filename submitted")
            return jsonify({'error': 'No file selected'}), 400
            
        # Validate file type
        if not validate_file(file.filename):
            logger.warning(f"Invalid file type: {file.filename}")
            return jsonify({
                'error': 'Invalid file type',
                'message': 'Supported types: Python, Java, JavaScript, C, C++, Ruby, HTML, PHP'
            }), 400
        
        try:
            # Ensure upload directory exists
            if not os.path.exists(UPLOAD_FOLDER):
                os.makedirs(UPLOAD_FOLDER)
                
            # Create a secure filename with timestamp to avoid conflicts
            timestamp = int(time.time())
            ext = os.path.splitext(file.filename)[1]
            secure_filename = f"upload_{timestamp}{ext}"
            file_path = os.path.join(UPLOAD_FOLDER, secure_filename)
            
            # Save the file
            file.save(file_path)
            logger.info(f"File saved successfully: {file_path}")
            
            # Read the file content with proper encoding handling
            code = None
            for encoding in ['utf-8', 'latin-1', 'cp1252', 'ascii']:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        code = f.read()
                        logger.info(f"Successfully read file with {encoding} encoding")
                        break
                except UnicodeDecodeError:
                    continue
            
            if code is None:
                raise ValueError("Unable to read file with any supported encoding")
            
            # Get file extension to determine language
            ext = os.path.splitext(file_path)[1].lower()
            language_map = {
                '.py': 'python',
                '.java': 'java',
                '.js': 'javascript',
                '.c': 'c',
                '.cpp': 'cpp',
                '.rb': 'ruby',
                '.php': 'php',
                '.html': 'html'
            }
            language = language_map.get(ext, 'plaintext')
            
            # Find vulnerabilities
            vulnerabilities = find_vulnerabilities(code, language)
            if vulnerabilities is None:
                vulnerabilities = []
            logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
            
            # Generate mitigations
            mitigations = generate_mitigations(vulnerabilities)
            
            # Count vulnerabilities
            vulnerability_types = [v['type'] for v in vulnerabilities]
            vulnerability_summary = {v: vulnerability_types.count(v) for v in set(vulnerability_types)}
            vulnerability_counts = [vulnerability_types.count(v) for v in set(vulnerability_types)]
            
            # Generate PDF report
            pdf_path = generate_pdf(file_path, vulnerabilities, vulnerability_summary, mitigations)
            logger.info(f"Generated PDF report: {pdf_path}")
            
            # Store results in session
            session['analysis_results'] = {
                'file_path': file_path,
                'vulnerabilities': vulnerabilities,
                'vulnerability_summary': vulnerability_summary,
                'vulnerability_types': list(set(vulnerability_types)),
                'vulnerability_counts': vulnerability_counts,
                'mitigations': mitigations,
                'pdf_path': pdf_path
            }
            
            logger.info("Analysis results stored in session")
            return redirect(url_for('result', file_path=file_path))
            
        except Exception as e:
            logger.error(f"Error processing file: {str(e)}", exc_info=True)
            return jsonify({
                'error': 'Error processing file',
                'message': str(e)
            }), 500
            
    except Exception as e:
        logger.error(f"Error in upload_file: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Server error',
            'message': 'An error occurred while uploading the file'
        }), 500

@app.route('/send_email_report', methods=['POST'])
def send_email_report():
    pdf_path = request.form['pdf_path']
    recipient = request.form['email']
    if not pdf_path or not recipient:
        flash('Invalid input.')
        return redirect(url_for('index'))
    send_email(recipient, 'Vulnerability Report', 'Please find the attached vulnerability report.', pdf_path)
    flash('Report sent successfully to {}'.format(recipient))
    return redirect(url_for('result', file_path=pdf_path))  # Redirect back to the result page

@app.route('/api/vulnerabilities', methods=['GET'])
@limiter.limit("30 per minute")
def get_vulnerabilities():
    try:
        # Fetch the latest uploaded file path
        latest_file = max([os.path.join(UPLOAD_FOLDER, f) for f in os.listdir(UPLOAD_FOLDER)], key=os.path.getctime)
        with open(latest_file, 'r') as f:
            code = f.read()
        vulnerabilities = find_vulnerabilities(code)
        vulnerability_types = [v['type'] for v in vulnerabilities]
        vulnerability_counts = [vulnerability_types.count(v) for v in set(vulnerability_types)]
        return {
            'vulnerability_types': list(set(vulnerability_types)),
            'vulnerability_counts': vulnerability_counts
        }
    except ValueError:
        # Handle the case where no files are uploaded yet
        return {
            'vulnerability_types': [],
            'vulnerability_counts': []
        }

@app.route('/download_pdf/<path:filename>', methods=['GET'])
def download_pdf(filename):
    return send_file(filename, as_attachment=True, mimetype='application/pdf')

def validate_file(filename):
    supported_extensions = ['py', 'java', 'js', 'c', 'cpp', 'rb', 'html', 'php']
    print(f"Filename: {filename}")
    if '.' in filename:
        extension = filename.rsplit('.', 1)[1].lower()
        print(f"Extension: {extension}")
        if extension in supported_extensions: return True
    return False

import base64

from google import genai
from google.genai import types


def generate_mitigations(vulnerabilities):
    # Skip API call if no vulnerabilities
    if not vulnerabilities:
        return {}
    
    client = genai.Client(
        api_key="AIzaSyAnpkkcIkqNUD1tnZ4l2o7x_hdbgOgD5ko",
    )

    # Prepare a more structured request for the API
    vulnerability_details = []
    for v in vulnerabilities:
        detail = f"Type: {v['type']}"
        if 'pattern' in v:
            detail += f", Pattern: {v['pattern']}"
        if 'line_number' in v:
            detail += f", Line: {v['line_number']}"
        if 'description' in v:
            detail += f", Description: {v['description']}"
        vulnerability_details.append(detail)
    
    vulnerability_text = "\n".join(vulnerability_details)
    
    model = "gemini-2.0-flash"
    prompt = f"""Analyze the following code vulnerabilities and provide specific mitigations for each vulnerability type:
    
{vulnerability_text}

For each vulnerability type, provide:
1. A clear, concise mitigation strategy
2. Example of corrected code when applicable
3. Best practices to prevent similar vulnerabilities

Format your response as plain text with clear sections for each vulnerability type."""

    contents = [
        types.Content(
            role="user",
            parts=[types.Part.from_text(text=prompt)],
        ),
    ]
    
    generate_content_config = types.GenerateContentConfig(
        temperature=0.7,
        top_p=0.95,
        top_k=40,
        max_output_tokens=8192,
        response_mime_type="text/plain",
    )

    # Get response from API
    mitigation_text = ""
    try:
        for chunk in client.models.generate_content_stream(
            model=model,
            contents=contents,
            config=generate_content_config,
        ):
            mitigation_text += chunk.text
    except Exception as e:
        logging.error(f"API error: {e}")
        mitigation_text = "Error generating mitigations. Please try again."
    
    # Create a dictionary where keys are vulnerability types
    mitigation_dict = {}
    # Get unique vulnerability types
    vuln_types = set(v['type'] for v in vulnerabilities)
    
    # Simple parsing - split the response by vulnerability types
    for vuln_type in vuln_types:
        # Find all text related to this vulnerability type in the API response
        if vuln_type in mitigation_text:
            # Extract the section for this vulnerability type
            start_idx = mitigation_text.find(vuln_type)
            next_vuln_idx = float('inf')
            
            # Find the next vulnerability type's position, if any
            for next_type in vuln_types:
                if next_type != vuln_type:
                    next_idx = mitigation_text.find(next_type, start_idx + len(vuln_type))
                    if next_idx > start_idx and next_idx < next_vuln_idx:
                        next_vuln_idx = next_idx
            
            # Extract the relevant part of the text
            if next_vuln_idx < float('inf'):
                mitigation_content = mitigation_text[start_idx:next_vuln_idx].strip()
            else:
                mitigation_content = mitigation_text[start_idx:].strip()
                
            mitigation_dict[vuln_type] = mitigation_content
        else:
            # Fallback if the API doesn't mention this vulnerability type
            mitigation_dict[vuln_type] = f"Mitigation for {vuln_type} not provided by the API."
    
    return mitigation_dict


def find_vulnerabilities(code, language=None):
    """Find vulnerabilities in the code with language-specific checks."""
    vulnerabilities = []
    
    # General vulnerability checks
    vulnerabilities.extend(find_code_injection_vulnerabilities(code))
    vulnerabilities.extend(find_sql_injection_vulnerabilities(code))
    vulnerabilities.extend(find_lfi_vulnerabilities(code))
    vulnerabilities.extend(find_rfi_vulnerabilities(code))
    vulnerabilities.extend(find_xss_vulnerabilities(code))
    vulnerabilities.extend(find_command_injection_vulnerabilities(code))
    vulnerabilities.extend(find_crypto_vulnerabilities(code))
    vulnerabilities.extend(find_redirect_vulnerabilities(code))
    vulnerabilities.extend(find_shell_vulnerabilities(code))
    vulnerabilities.extend(find_upload_vulnerabilities(code))
    
    # Language-specific vulnerability checks
    if language:
        if language == 'c':
            from vulnerabilities.c_lang.vulnerabilities import find_c_vulnerabilities
            vulnerabilities.extend(find_c_vulnerabilities(code))
        elif language == 'python':
            from vulnerabilities.python.vulnerabilities import find_python_vulnerabilities
            vulnerabilities.extend(find_python_vulnerabilities(code))
        elif language == 'java':
            from vulnerabilities.java.vulnerabilities import find_java_vulnerabilities
            vulnerabilities.extend(find_java_vulnerabilities(code))
        elif language == 'javascript':
            from vulnerabilities.javascript.vulnerabilities import find_javascript_vulnerabilities
            vulnerabilities.extend(find_javascript_vulnerabilities(code))
    
    return vulnerabilities

def generate_mitigated_code(code, language, vulnerabilities):
    """Generate mitigated version of the code based on detected vulnerabilities."""
    try:
        if not code or not vulnerabilities:
            return code

        mitigated_code = code
        
        # Sort vulnerabilities by line number in reverse order to avoid offset issues
        sorted_vulnerabilities = sorted(
            vulnerabilities, 
            key=lambda x: x.get('line_number', 0), 
            reverse=True
        )

        # Language-specific mitigation templates
        mitigation_templates = {
            'php': {
                'command_injection': {
                    'pattern': r'shell_exec\((.*?)\)',
                    'replacement': 'escapeshellcmd($1)'
                },
                'sql_injection': {
                    'pattern': r'mysql_query\((.*?)\)',
                    'replacement': '$stmt = $pdo->prepare($1); $stmt->execute($params);'
                },
                'xss': {
                    'pattern': r'echo (.*?);',
                    'replacement': 'echo htmlspecialchars($1, ENT_QUOTES, \'UTF-8\');'
                }
            },
            'python': {
                'command_injection': {
                    'pattern': r'os\.system\((.*?)\)',
                    'replacement': 'subprocess.run([$1], shell=False, check=True)'
                },
                'sql_injection': {
                    'pattern': r'execute\((.*?)\)',
                    'replacement': 'execute(query, params)'
                }
            }
        }

        # Get language-specific templates
        templates = mitigation_templates.get(language, {})
        
        # Apply mitigations based on vulnerability type
        for vuln in sorted_vulnerabilities:
            vuln_type = vuln.get('type', '').lower().replace(' ', '_')
            line_number = vuln.get('line_number', 0)
            
            if line_number > 0:
                # Get the specific line
                lines = mitigated_code.splitlines()
                if line_number <= len(lines):
                    original_line = lines[line_number - 1]
                    mitigated_line = original_line

                    # Apply language-specific mitigation if available
                    if vuln_type in templates:
                        pattern = templates[vuln_type]['pattern']
                        replacement = templates[vuln_type]['replacement']
                        mitigated_line = re.sub(pattern, replacement, original_line)
                    else:
                        # Generic mitigations based on vulnerability type
                        if 'sql_injection' in vuln_type:
                            mitigated_line = add_sql_injection_mitigation(original_line, language)
                        elif 'xss' in vuln_type:
                            mitigated_line = add_xss_mitigation(original_line, language)
                        elif 'command_injection' in vuln_type:
                            mitigated_line = add_command_injection_mitigation(original_line, language)
                        elif 'path_traversal' in vuln_type:
                            mitigated_line = add_path_traversal_mitigation(original_line, language)
                    
                    # Add comment explaining the mitigation
                    mitigated_line = f"{mitigated_line}  // Mitigated {vuln.get('type')}"
                    
                    # Replace the line in the code
                    lines[line_number - 1] = mitigated_line
                    mitigated_code = '\n'.join(lines)

        return mitigated_code
    except Exception as e:
        logger.error(f"Error generating mitigated code: {str(e)}")
        return code  # Return original code if mitigation fails

def add_sql_injection_mitigation(line, language):
    """Add SQL injection mitigation based on language."""
    if language == 'php':
        return line.replace('mysql_query', 'prepare')
    elif language == 'python':
        return line.replace('%s', '?').replace('+', ',')
    return line

def add_xss_mitigation(line, language):
    """Add XSS mitigation based on language."""
    if language == 'php':
        return line.replace('echo', 'echo htmlspecialchars')
    elif language == 'python':
        return line.replace('render_template', 'render_template|safe')
    return line

def add_command_injection_mitigation(line, language):
    """Add command injection mitigation based on language."""
    if language == 'php':
        return line.replace('shell_exec', 'escapeshellcmd')
    elif language == 'python':
        return line.replace('os.system', 'subprocess.run([],shell=False)')
    return line

def add_path_traversal_mitigation(line, language):
    """Add path traversal mitigation based on language."""
    if language == 'php':
        return line.replace('file_get_contents', 'realpath')
    elif language == 'python':
        return line.replace('open', 'os.path.abspath')

@app.route('/security_report/<path:report_name>')
def security_report(report_name):
    """Serve security report files."""
    try:
        return send_from_directory(SECURITY_REPORTS_DIR, report_name)
    except Exception as e:
        logger.error(f"Error serving security report: {str(e)}")
        flash('Error accessing security report.')
        return redirect(url_for('index'))

@app.route('/compare/<path:file_path>')
def compare_code(file_path):
    try:
        # Check if file exists first
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            flash('File not found.')
            return redirect(url_for('index'))

        # Check session
        if 'analysis_results' not in session:
            logger.warning("No analysis results found in session")
            flash('No analysis results found.')
            return redirect(url_for('index'))
        
        results = session.get('analysis_results', {})
        logger.info(f"Retrieved analysis results from session: {bool(results)}")
        
        # Read file content using the file handler
        original_code, encoding = read_file_with_encoding(file_path)
        if original_code is None:
            logger.error("Failed to read file content")
            flash('Error reading file.')
            return redirect(url_for('index'))
            
        logger.info(f"Original code length: {len(original_code)}")
        
        # Get language using the file handler
        language = get_file_language(file_path)
        logger.info(f"Detected language: {language} for file: {file_path}")
        
        # Get vulnerabilities from session
        vulnerabilities = results.get('vulnerabilities', [])
        logger.info(f"Number of vulnerabilities found: {len(vulnerabilities)}")
        
        # Initialize default values
        verification_results = {'security_improvements': [], 'remaining_issues': []}
        remaining_vulns = []
        quality_metrics = {
            'metrics': {
                'complexity': 0,
                'maintainability': 0.0,
                'test_coverage': 0.0,
                'security_score': 0.0
            },
            'recommendations': []
        }
        report_url = None
        
        # Generate mitigated code
        try:
            if not vulnerabilities:
                mitigated_code = "// No vulnerabilities found in the code."
                logger.info("No vulnerabilities found, using placeholder message")
            else:
                mitigated_code = generate_mitigated_code(original_code, language, vulnerabilities)
                if not mitigated_code:
                    logger.warning("Generated mitigated code is empty")
                    mitigated_code = "// Error: Failed to generate mitigated code"
                else:
                    logger.info(f"Generated mitigated code length: {len(mitigated_code)}")
                    
                    # Verify mitigations
                    try:
                        verification_results = security_verifier.verify_mitigations(original_code, mitigated_code, language)
                    except Exception as e:
                        logger.error(f"Error verifying mitigations: {str(e)}")
                    
                    # Find any remaining vulnerabilities
                    try:
                        remaining_vulns = security_verifier.find_remaining_vulnerabilities(mitigated_code, language)
                    except Exception as e:
                        logger.error(f"Error finding remaining vulnerabilities: {str(e)}")
                    
                    # Ensure code quality
                    try:
                        quality_metrics = security_verifier.ensure_code_quality(mitigated_code, language)
                    except Exception as e:
                        logger.error(f"Error ensuring code quality: {str(e)}")
                    
                    # Generate security report
                    try:
                        report_filename = security_verifier.generate_security_report(mitigated_code, language, file_path)
                        if report_filename:
                            report_name = os.path.basename(report_filename)
                            report_url = url_for('security_report', report_name=report_name)
                    except Exception as e:
                        logger.error(f"Error generating security report: {str(e)}")
                    
                    logger.info("Security verification completed successfully")
                    
        except Exception as e:
            logger.error(f"Error generating mitigated code: {str(e)}")
            mitigated_code = f"// Error generating mitigated code: {str(e)}\n// Please try again."
        
        # Debug logging
        logger.debug(f"Original code preview: {original_code[:100]}...")
        logger.debug(f"Mitigated code preview: {mitigated_code[:100]}...")
        
        # Ensure code is properly escaped for JSON
        try:
            original_code_json = json.dumps(original_code)
            mitigated_code_json = json.dumps(mitigated_code)
            logger.info("Successfully encoded code as JSON")
        except Exception as e:
            logger.error(f"Error encoding code as JSON: {str(e)}")
            original_code_json = json.dumps("// Error: Could not load code")
            mitigated_code_json = json.dumps("// Error: Could not load code")
        
        # Store the current state in session
        session['compare_state'] = {
            'file_path': file_path,
            'language': language,
            'original_code': original_code_json,
            'mitigated_code': mitigated_code_json
        }
        
        # Render template with all necessary data
        return render_template(
            'compare.html',
            original_code=original_code_json,
            mitigated_code=mitigated_code_json,
            language=language,
            vulnerabilities=vulnerabilities,
            file_path=file_path,
            verification_results=verification_results,
            remaining_vulnerabilities=remaining_vulns,
            quality_metrics=quality_metrics,
            security_report=report_url
        )
        
    except Exception as e:
        logger.error(f"Unexpected error in compare_code: {str(e)}", exc_info=True)
        flash('An error occurred while comparing code.')
        return redirect(url_for('index'))

# Error handlers
@app.errorhandler(400)
def bad_request(error):
    logger.error(f"Bad request: {error}")
    return jsonify({'error': 'Bad request', 'message': str(error)}), 400

@app.errorhandler(404)
def not_found(error):
    logger.error(f"Not found: {error}")
    return jsonify({'error': 'Not found', 'message': str(error)}), 404

@app.errorhandler(429)
def ratelimit_handler(error):
    logger.warning(f"Rate limit exceeded: {error}")
    return jsonify({'error': 'Rate limit exceeded', 'message': str(error)}), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error', 'message': str(error)}), 500

@app.route('/generate_mitigation', methods=['POST'])
@limiter.limit("5 per minute")
def generate_mitigation():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        code = data.get('code')
        language = data.get('language')
        
        if not code:
            return jsonify({'error': 'No code provided'}), 400
        if not language:
            return jsonify({'error': 'No language specified'}), 400
            
        logger.info(f"Generating mitigation for {language} code")
            
        # Find vulnerabilities in the code
        vulnerabilities = find_vulnerabilities(code, language)
        
        if not vulnerabilities:
            return jsonify({
                'mitigated_code': code,
                'message': 'No vulnerabilities found to mitigate.',
                'vulnerabilities': []
            })
        
        # Generate mitigated code using the AI model
        try:
            mitigated_code = generate_mitigated_code(code, language, vulnerabilities)
            if not mitigated_code or mitigated_code.startswith('// Error'):
                raise ValueError("Failed to generate mitigated code")

            # Verify mitigations
            verification_results = security_verifier.verify_mitigations(code, mitigated_code, language)
            
            # Find any remaining vulnerabilities
            remaining_vulns = security_verifier.find_remaining_vulnerabilities(mitigated_code, language)
            
            # Ensure code quality
            quality_metrics = security_verifier.ensure_code_quality(mitigated_code, language)
            
            # Generate security report with a unique filename
            timestamp = int(time.time())
            report_filename = f"security_report_{timestamp}.json"
            report_path = os.path.join(SECURITY_REPORTS_DIR, report_filename)
            
            # Save the report
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'language': language,
                'vulnerabilities': vulnerabilities,
                'verification_results': verification_results,
                'remaining_vulnerabilities': remaining_vulns,
                'quality_metrics': quality_metrics
            }
            
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2)
                
            return jsonify({
                'mitigated_code': mitigated_code,
                'vulnerabilities': vulnerabilities,
                'verification_results': verification_results,
                'remaining_vulnerabilities': remaining_vulns,
                'quality_metrics': quality_metrics,
                'security_report': report_filename,
                'message': 'Successfully generated mitigated code'
            })
            
        except Exception as e:
            logger.error(f"Error generating mitigated code: {str(e)}", exc_info=True)
            return jsonify({
                'error': 'Failed to generate mitigated code',
                'message': str(e)
            }), 500
        
    except Exception as e:
        logger.error(f"Error in generate_mitigation: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Error processing request',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    try:
        from config.flask_config import create_app, run_app
        app = create_app()
        print("Starting Secure Vigil server...")
        print("Access the application at http://localhost:5000")
        run_app(app)
    except Exception as e:
        print(f"Error starting server: {str(e)}")
        # Fallback to Flask's development server
        app.run(host='0.0.0.0', port=5000, debug=True)

