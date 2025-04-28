import os
import datetime
import uuid
import subprocess
import zipfile
from flask import Flask, render_template, request, redirect, url_for, jsonify
from modules.vulnerability import check_vulnerabilities_local
from modules.dependency import build_dependency_tree, visualize_dependency_tree
from modules.history import save_to_history, get_scan_by_uuid, load_history
from modules.sast_scanner import perform_sast_scan
from modules.dast_scanner import perform_dast_scan

import tempfile
from flask import make_response

app = Flask(__name__)

# Configuration
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["STATIC_FOLDER"] = "static"
app.config["DEPENDENCY_GRAPH_FOLDER"] = os.path.join(app.config["STATIC_FOLDER"], "dependency_graphs")
history_file = "scan_history.json"

# Ensure folders exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["DEPENDENCY_GRAPH_FOLDER"], exist_ok=True)

import zipfile
import os

def extract_dependencies_from_file(file_content, file_name):
    """Extract package dependencies from the uploaded file."""
    dependencies = {}

    if file_name.endswith('.txt'):
        # Process text files like requirements.txt
        for line in file_content.splitlines():
            # Ignore comments and empty lines
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Extract package name and version (if present)
            if "==" in line:
                package_info = line.split("==")
                package_name = package_info[0]
                version = package_info[1]
            else:
                package_name = line
                version = ""
            
            # Add to dictionary where package_name is key, and version is the value
            if package_name not in dependencies:
                dependencies[package_name] = []
            dependencies[package_name].append(version)

    elif file_name.endswith('.zip'):
        # Process .zip file containing Python packages
        try:
            # Create a temporary directory to extract ZIP contents
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(file_content, 'r') as zip_ref:
                    # Extract all contents to the temporary directory
                    zip_ref.extractall(temp_dir)
                
                # Create a list of directories ending with .dist-info/
                dist_info_folders = []
                for root, dirs, files in os.walk(temp_dir):
                    for dir_name in dirs:
                        # Check for directories ending with .dist-info
                        if dir_name.endswith('.dist-info'):
                            dist_info_folders.append(os.path.join(root, dir_name))
                
                # Now loop through those folders to extract package name and version
                for folder in dist_info_folders:
                    # Folder structure like package-name-version.dist-info
                    folder_name = os.path.basename(folder)
                    parts = folder_name.split('-')
                    if len(parts) >= 2:
                        package_name = parts[0]
                        version = parts[1].strip('.dist-info')
                        
                        if package_name not in dependencies:
                            dependencies[package_name] = []
                        dependencies[package_name].append(version)
        except zipfile.BadZipFile:
            print("The provided file is not a valid ZIP file.")
    
    return dependencies

def get_package_metadata(package_name):
    """Fetch metadata for a package using pip show."""
    try:
        result = subprocess.run(
            ['pip', 'show', package_name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode == 0:
            metadata = {}
            for line in result.stdout.splitlines():
                if line.startswith("Name:"):
                    metadata["name"] = line.split(":")[1].strip()
                elif line.startswith("Version:"):
                    metadata["version"] = line.split(":")[1].strip()
                elif line.startswith("License:"):
                    metadata["license"] = line.split(":")[1].strip()
            return metadata
        else:
            print(f"Error fetching metadata for package {package_name}: {result.stderr}")
            return None
    except Exception as e:
        print(f"Exception occurred while fetching metadata for {package_name}: {e}")
        return None

# Dependency scanner
@app.route("/")
def index():
    # Check if session_id exists in cookies
    session_id = request.cookies.get("session_id")
    if not session_id:
        # Generate a new UUID
        session_id = str(uuid.uuid4())

    # Create a response object
    response = make_response(render_template("index.html"))
    # Set the session_id in cookies
    response.set_cookie("session_id", session_id, httponly=True, samesite="Strict")

    return response

@app.route("/scan")
def scanpage():
    return render_template("filescan.html")

@app.route("/scan", methods=["POST"])
def scan():
    file = request.files.get("file")
    # Get a list of selected license compliance values
    selected_compliance = request.form.getlist("license_compliance")

    if not file:
        return jsonify({"error": "No file uploaded."}), 400

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(file_path)

    scan_uuid = str(uuid.uuid4())
    session_id = request.cookies.get("session_id")  # Retrieve session_id from cookies

    # Read and process the uploaded file to extract package information
    if file.filename.endswith('.txt'):
        # Process .txt file
        with open(file_path, 'r') as f:
            file_content = f.read()

        # Extract dependencies from .txt file
        dependencies = extract_dependencies_from_file(file_content, file.filename)
    
    elif file.filename.endswith('.zip'):
        # Process .zip file
        dependencies = extract_dependencies_from_file(file_path, file.filename)
        print(dependencies)
    else:
        return jsonify({"error": "Invalid file type. Only .txt and .zip are supported."}), 400
    
    # Build the dependency tree based on the extracted dependencies
    dependency_tree = build_dependency_tree(dependencies)  # Fetch the full dependency tree
    
    # Visualize the dependency tree
    dependency_graph_filename = visualize_dependency_tree(
        dependency_tree, app.config["DEPENDENCY_GRAPH_FOLDER"], scan_uuid
    )
    
    # Check vulnerabilities for each package with its version
    vulnerabilities = []
    for package, versions in dependencies.items():
        for version in versions:
            vulnerabilities.extend(check_vulnerabilities_local(package, version))  # Scan package for vulnerabilities

    # Define severity weights
    severity_weights = {
        'Critical': 5,  # Highest weight for Critical
        'High': 4,      # Second highest weight for High
        'Medium': 2,    # Medium severity weight
        'Low': 1        # Lowest weight for Low
    }

    # Calculate severity score (based on vulnerabilities found)
    severity_score = 0
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'Low')  # Default to 'Low' if severity is not found
        severity_score += severity_weights.get(severity, 1)  # Add the corresponding severity weight

    # Check license compliance for each package
    compliance_status = []
    for package in dependencies:
        metadata = get_package_metadata(package)
        if metadata:
            license_info = metadata.get("license")
            if license_info and license_info in selected_compliance:
                compliance_status.append(f"{package}: Compliant")
            else:
                compliance_status.append(f"{package}: Not compliant")
        else:
            compliance_status.append(f"{package}: Metadata not found")

    # Compile the final scan data
    scan_data = {
        "uuid": scan_uuid,
        "session_id": session_id,  # Save session ID here
        "timestamp": datetime.datetime.now().isoformat(),
        "file": file.filename,
        "severity_score": severity_score,
        "vulnerabilities": vulnerabilities,
        "license_compliance": compliance_status,
        "selected_license_compliance": selected_compliance,  # Add the list of selected license compliance
        "dependency_graph": f"dependency_graphs/{dependency_graph_filename}",
        "scantype": "dependency_scan",
    }

    print(scan_data)

    # Save scan result to history
    save_to_history(scan_data)

    return redirect(url_for("scan_result", uuid=scan_uuid))

@app.route("/scan-api", methods=["POST"])
def scan_api():
    file = request.files.get("file")
    selected_compliance = request.form.getlist("license_compliance")

    if not file:
        return jsonify({"error": "No file uploaded."}), 400

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(file_path)

    scan_uuid = str(uuid.uuid4())
    session_id = request.cookies.get("session_id")

    # Process the uploaded file
    if file.filename.endswith('.txt'):
        with open(file_path, 'r') as f:
            file_content = f.read()
        dependencies = extract_dependencies_from_file(file_content, file.filename)

    elif file.filename.endswith('.zip'):
        dependencies = extract_dependencies_from_file(file_path, file.filename)
    else:
        return jsonify({"error": "Invalid file type. Only .txt and .zip are supported."}), 400

    dependency_tree = build_dependency_tree(dependencies)
    dependency_graph_filename = visualize_dependency_tree(
        dependency_tree, app.config["DEPENDENCY_GRAPH_FOLDER"], scan_uuid
    )

    vulnerabilities = []
    for package, versions in dependencies.items():
        for version in versions:
            vulnerabilities.extend(check_vulnerabilities_local(package, version))

    severity_weights = {'Critical': 5, 'High': 4, 'Medium': 2, 'Low': 1}
    severity_score = sum(severity_weights.get(vuln.get('severity', 'Low'), 1) for vuln in vulnerabilities)

    compliance_status = []
    for package in dependencies:
        metadata = get_package_metadata(package)
        if metadata:
            license_info = metadata.get("license")
            compliance_status.append(
                f"{package}: Compliant" if license_info and license_info in selected_compliance else f"{package}: Not compliant"
            )
        else:
            compliance_status.append(f"{package}: Metadata not found")

    scan_data = {
        "uuid": scan_uuid,
        "session_id": session_id,
        "timestamp": datetime.datetime.now().isoformat(),
        "file": file.filename,
        "severity_score": severity_score,
        "vulnerabilities": vulnerabilities,
        "license_compliance": compliance_status,
        "selected_license_compliance": selected_compliance,
        "dependency_graph": f"dependency_graphs/{dependency_graph_filename}",
        "scantype": "dependency_scan",
    }

    save_to_history(scan_data)

    return jsonify(scan_data), 200

@app.route("/scan_result/<uuid>", methods=["GET"])
def scan_result(uuid):
    # Fetch scan data using the imported get_scan_by_uuid function
    scan_data = get_scan_by_uuid(uuid,"dependency_scan")
    if not scan_data:
        return "Scan not found", 404
    return render_template("result.html", scan=scan_data)

# sast dast
@app.route('/sast-dast')
def sastdast():
    return render_template('sast_dast.html')

# Endpoint for SAST
@app.route('/sast-upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    session_id = request.cookies.get("session_id")  # Retrieve session_id from cookies

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    # Perform SAST Scan
    report = perform_sast_scan(filepath,session_id)
    print(report)
    # Save scan result to history
    save_to_history(report)

    return render_template('sast_result.html', sast_report=report)

# Endpoint for DAST
@app.route('/dast-scan', methods=['POST'])
def scan_url():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    session_id = request.cookies.get("session_id")  # Retrieve session_id from cookies

    # Perform DAST Scan
    report = perform_dast_scan(url,session_id)
    print(report)
    # Save scan result to history
    save_to_history(report)

    return render_template('dast_result.html', dast_report=report)

@app.route("/history")
def history():
    session_id = request.cookies.get("session_id")
    if not session_id:
        return "Session not found. Please log in.", 401

    history = load_history()
    if not isinstance(history, list):
        return "Invalid history data.", 500

    filtered_history = [entry for entry in history if isinstance(entry, dict) and entry.get("session_id") == session_id]
    return render_template("history.html", history=filtered_history)

@app.route("/historyfilter", methods=["POST"])
def filter_history():
    session_id = request.cookies.get("session_id")
    
    if not session_id:
        return jsonify({"error": "Session not found"}), 401

    scantype = request.json.get("scantype")
    
    if not scantype:
        return jsonify({"error": "Scantype is required"}), 400
    
    # Load history from wherever it is stored (e.g., a database or file)
    history = load_history()

    # Log the session and scantype for debugging
    print(f"Session ID: {session_id}")
    print(f"Scantype: {scantype}")

    # Ensure 'history' is a list and each 'entry' is a dictionary
    if not isinstance(history, list):
        return jsonify({"error": "Invalid history data"}), 500
    
    # Filtering the history based on session_id and scantype
    filtered_history = [
        entry for entry in history
        if isinstance(entry, dict) and 
        entry.get("session_id") == session_id and
        entry.get("scantype") == scantype
    ]
    
    # Log filtered history to see what's being returned
    print(f"Filtered History: {filtered_history}")
    
    # Return filtered history
    return jsonify(filtered_history)

from urllib.parse import urlparse
import time
import ssl
import socket

# Function to analyze cipher suites
def analyze_cipher_suites(host, retries=3, timeout=10):
    """
    Analyzes the cipher suites supported by a server using Python's ssl library.
    Flags weak cipher suites or any vulnerabilities.
    """
    weak_ciphers = ["RC4", "3DES", "MD5"]
    analysis_results = []

    parsed_url = urlparse(host)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    if not domain:
        return ["Error: Invalid URL provided."]
    
    print(f"Command: Connecting to {domain}:443...")

    attempt = 0
    while attempt < retries:
        try:
            print(f"Attempting to connect to {domain}:443... (Attempt {attempt + 1}/{retries})")

            # Establish SSL context and socket connection
            context = ssl.create_default_context()
            connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)

            connection.settimeout(timeout)
            connection.connect((domain, 443))
            
            # Get the supported cipher suites
            cipher = connection.cipher()
            print(f"Connected using cipher: {cipher}")

            if cipher:
                cipher_name = cipher[0]
                for weak_cipher in weak_ciphers:
                    if weak_cipher in cipher_name:
                        analysis_results.append(f"Warning: Weak cipher suite detected: {cipher_name}")

            if not analysis_results:
                analysis_results.append("No weak cipher suites found.")
            
            connection.close()
            return analysis_results

        except socket.timeout:
            attempt += 1
            analysis_results.append(f"Error: Connection timed out. Retrying ({attempt}/{retries})...")
            time.sleep(3)
        except Exception as e:
            analysis_results.append(f"Unexpected error: {str(e)}")
            return analysis_results
    
    analysis_results.append(f"Error: Could not connect to {domain} after {retries} attempts.")
    return analysis_results

@app.route('/cipher-suite-form', methods=['GET', 'POST'])
def cipher_suite_form():
    if request.method == 'POST':
        host = request.form.get('host')
        if not host:
            return jsonify({'error': 'No host provided'}), 400

        # Call the Cipher Suite analysis function
        results = analyze_cipher_suites(host)

        # Save to history
        scan_uuid = str(uuid.uuid4())
        session_id = request.cookies.get("session_id")
        
        scan_data = {
            "uuid": scan_uuid,
            "session_id": session_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "host": host,
            "results": results,
            "scantype": "cipher_suite_scan"
        }

        save_to_history(scan_data)

        return render_template('cipher_suite_result.html', results=results)
    
    return render_template('cipher_suite_form.html')

def analyze_dockerfile(filepath):
    issues = []

    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()

        user_declared = False
        has_healthcheck = False

        for idx, line in enumerate(lines):
            line = line.strip()
            lineno = idx + 1

            if line.startswith('FROM') and 'latest' in line:
                issues.append((lineno, "Avoid using 'latest' tag in FROM instruction."))

            if line.startswith('ADD '):
                issues.append((lineno, "Use COPY instead of ADD unless you need tar auto-extraction."))

            if 'curl' in line and ('|' in line) and 'bash' in line:
                issues.append((lineno, "Avoid piping curl output directly into bash (insecure)."))

            if 'wget' in line and ('|' in line) and 'bash' in line:
                issues.append((lineno, "Avoid piping wget output directly into bash (insecure)."))

            if line.startswith('USER'):
                user_declared = True
                if 'root' in line:
                    issues.append((lineno, "Avoid running containers as root user."))

            if 'HEALTHCHECK' in line:
                has_healthcheck = True

            if any(secret in line.lower() for secret in ['password', 'secret', 'apikey', 'token']):
                issues.append((lineno, "Potential hardcoded secret found."))

        if not user_declared:
            issues.append((0, "No USER declared. Containers run as root by default, which is insecure."))

        if not has_healthcheck:
            issues.append((0, "No HEALTHCHECK specified. It's recommended to monitor container health."))

    except Exception as e:
        issues.append((0, f"Error reading Dockerfile: {str(e)}"))

    return issues

@app.route("/container-scan", methods=["GET", "POST"])
def container_scan():
    """Handle Dockerfile upload and static analysis"""
    if request.method == 'POST':
        file = request.files.get("container_image")
        
        if not file:
            return jsonify({"error": "No Dockerfile uploaded."}), 400

        # Only allow Dockerfile uploads
        if not file.filename.lower().endswith("dockerfile"):
            return jsonify({"error": "Please upload a valid Dockerfile."}), 400

        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)

        # Analyze Dockerfile
        issues = analyze_dockerfile(filepath)

        # Create scan UUID and session ID
        scan_uuid = str(uuid.uuid4())
        session_id = request.cookies.get("session_id")

        # Save to history
        scan_data = {
            "uuid": scan_uuid,
            "session_id": session_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "file": file.filename,
            "issues": issues,
            "scantype": "dockerfile_scan"
        }

        save_to_history(scan_data)

        return render_template("container_scan_result.html", issues=issues, filename=file.filename)

    return render_template("container_scan_form.html")

if __name__ == "__main__":
    app.run(debug=True)
