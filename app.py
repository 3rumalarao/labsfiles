# app.py
import os
from flask import Flask, request, jsonify, render_template

# --- NEW: Imports for Certificate Check ---
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

# --- Use the NEW Azure client ---
import azure_openai_client

# --- Keep existing file handling imports (but leave /upload route as is) ---
from file_handling import extract_data_from_pdf, extract_text_from_excel, extract_text_from_word, extract_text_from_txt

# --- Remove old client import ---
# from chatgpt import ChatGPT # REMOVED

app = Flask(__name__, template_folder='templates', static_folder='static')

# --- Remove old client instantiation ---
# chatgpt = ChatGPT() # REMOVED

# --- NEW: Certificate Expiry Check Function ---
def get_certificate_expiry(url_string):
    """
    Checks the SSL/TLS certificate expiry for a given domain/URL.
    Handles HTTP URLs and connection errors gracefully.
    """
    hostname = None
    port = 443
    connect_timeout = 5 # seconds for connection attempt
    ssl_timeout = 5 # seconds for SSL handshake

    try:
        # Ensure input is treated as a potential URL for parsing
        if '://' not in url_string:
            # Assume https if no scheme, helps urlparse
            url_string_for_parse = 'https://' + url_string
        else:
            url_string_for_parse = url_string

        parsed_url = urlparse(url_string_for_parse)
        hostname = parsed_url.hostname
        scheme = parsed_url.scheme

        if not hostname:
            return "Error: Could not extract a valid hostname from the input."

        # --- Handle HTTP explicitly ---
        if scheme == 'http':
            return "Error: Cannot check certificate for HTTP URLs. Only HTTPS is supported."

        # --- Attempt HTTPS connection (scheme is https or was assumed) ---
        print(f"Attempting HTTPS connection to {hostname}:{port}")
        context = ssl.create_default_context()
        # context.check_hostname = False # Optional: Disable hostname verification if needed, less secure
        # context.verify_mode = ssl.CERT_NONE # Optional: Disable CA verification if needed, less secure

        with socket.create_connection((hostname, port), timeout=connect_timeout) as sock:
            print(f"TCP connection successful. Performing SSL handshake...")
            with context.wrap_socket(sock, server_hostname=hostname, do_handshake_on_connect=True, suppress_ragged_eofs=True) as sslsock:
                sslsock.settimeout(ssl_timeout) # Timeout for SSL operations
                cert = sslsock.getpeercert()
                print("SSL handshake successful. Certificate received.")

                if not cert:
                    return f"Error: Server {hostname} provided no certificate after successful SSL handshake."

                expiry_date_str = cert.get('notAfter')
                if not expiry_date_str:
                     return f"Error: Certificate found for {hostname}, but expiry date ('notAfter') is missing."

                # Convert to datetime object
                expiry_date = ssl.cert_time_to_datetime(expiry_date_str)
                return f"The certificate for '{hostname}' expires on: {expiry_date.strftime('%Y-%m-%d %H:%M:%S %Z')}"

    except socket.gaierror:
        return f"Error: Could not resolve hostname '{hostname or url_string}' (DNS lookup failed)."
    except socket.timeout:
        # Distinguish between connection and SSL timeout if possible, but often shows as socket.timeout
        return f"Error: Connection timed out trying to reach '{hostname or url_string}' on port {port}."
    except ConnectionRefusedError:
         return f"Error: Connection refused by '{hostname or url_string}' on port {port}. HTTPS may not be running."
    except ssl.SSLCertVerificationError as e:
         # Only relevant if verify_mode is not CERT_NONE
         print(f"SSL Certificate Verification Error for {hostname}: {e}")
         return f"Error: Certificate verification failed for '{hostname}': {e.reason}"
    except ssl.SSLError as e:
        # Catch various SSL handshake or protocol errors
        print(f"SSL Error connecting to {hostname}: {e}")
        return f"Error: An SSL error occurred connecting to '{hostname}'. It might not support HTTPS properly or has configuration issues. (Reason: {e.reason})"
    except ValueError as e: # Handle potential errors from cert_time_to_datetime
        return f"Error: Could not parse certificate date for '{hostname}': {e}"
    except OSError as e:
         # Catch other potential network errors like "No route to host"
         print(f"OS Error connecting to {hostname}: {e}")
         return f"Error: Network error connecting to '{hostname}': {e.strerror}"
    except Exception as e:
        # Catch-all for other unexpected errors
        print(f"ERROR: Unexpected error checking certificate for {url_string}: {e}")
        return f"Error: An unexpected error occurred while checking the certificate for '{hostname or url_string}'."


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/chat', methods=['POST'])
def chat():
    """Handles chat messages: checks for domain/URL for cert check, otherwise uses Azure OpenAI."""
    if not request.is_json:
         return jsonify({"response": "Error: Request must be JSON"}), 400

    user_message = request.json.get('message')
    if not user_message:
        return jsonify({'response': 'Error: No message received'}), 400

    response_text = None
    input_text = user_message.strip()

    # --- Logic to decide action ---
    # Basic check: Does it contain a dot and no spaces? Or start with http/https?
    # More robust regex could be used, but this is a simple heuristic.
    is_potential_domain = (
        ( '.' in input_text and ' ' not in input_text and len(input_text) > 3 ) or
        input_text.lower().startswith(('http://', 'https://'))
    )

    if is_potential_domain:
        print(f"Input '{input_text}' detected as potential domain/URL. Checking certificate...")
        response_text = get_certificate_expiry(input_text)
    else:
        # Not a domain/URL, treat as a general chat message
        print(f"Input '{input_text}' not detected as domain. Sending to Azure OpenAI...")
        response_text = azure_openai_client.get_chat_response(user_message)

    # Fallback if something went wrong in the logic above
    if response_text is None:
        response_text = "Sorry, an internal error occurred processing your request."

    return jsonify({'response': response_text})

# --- /upload route remains UNCHANGED ---
@app.route('/upload', methods=['POST'])
def upload_file():
    # This code is kept exactly as you provided it
    file = request.files['file']
    # Basic check if file exists
    if not file or file.filename == '':
         return jsonify({'response': 'No file selected'}), 400

    # Ensure uploads directory exists (add this check here)
    upload_dir = 'uploads'
    try:
        os.makedirs(upload_dir, exist_ok=True)
    except OSError as e:
        print(f"Error creating upload directory '{upload_dir}': {e}")
        return jsonify({'response': f'Server error: Could not create upload directory.'}), 500

    file_path = os.path.join(upload_dir, file.filename) # Use secure_filename later if needed

    # Save the file (add error handling)
    try:
        file.save(file_path)
        print(f"File saved to {file_path}")
    except Exception as e:
         print(f"Error saving file {file.filename}: {e}")
         return jsonify({'response': f'Server error: Could not save file {file.filename}.'}), 500

    text = None # Initialize text
    try:
        if file.filename.endswith('.pdf'):
            text = extract_data_from_pdf(file_path)
            print("PDF Content Extracted (first 100 chars):\n", text[:100] if text else "None")
        elif file.filename.endswith('.xlsx') or file.filename.endswith('.xls'):
            text = extract_text_from_excel(file_path)
            print("Excel Content Extracted (first 100 chars):\n", text[:100] if text else "None")
        elif file.filename.endswith('.docx'):
            text = extract_text_from_word(file_path)
            print("Word Content Extracted (first 100 chars):\n", text[:100] if text else "None")
        elif file.filename.endswith('.txt'):
            text = extract_text_from_txt(file_path)
            print("Text file Content Extracted (first 100 chars):\n", text[:100] if text else "None")
        else:
            # Clean up file if unsupported
            if os.path.exists(file_path): os.remove(file_path)
            return jsonify({'response': 'Unsupported file format'}), 400

        # --- IMPORTANT: Cleanup the saved file ---
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"Removed temporary file: {file_path}")
            except Exception as e:
                print(f"Error removing temporary file {file_path}: {e}")
        # -----------------------------------------

        # Check if extraction failed (assuming functions return None or raise exceptions on failure)
        if text is None:
             # This might happen if the extraction function itself failed silently or file was empty
             return jsonify({'response': 'Could not extract text from the file.'}), 400

        # Return raw extracted text as per original code
        return jsonify({'response': text})

    except Exception as e:
         # Catch errors during extraction
         print(f"Error during file extraction for {file.filename}: {e}")
         # Clean up file if extraction failed
         if os.path.exists(file_path):
             try: os.remove(file_path)
             except Exception as remove_e: print(f"Error removing file after extraction error: {remove_e}")
         return jsonify({'response': f'Error processing file: {e}'}), 500


if __name__ == '__main__':
    print("\n--- Starting Flask App ---")
    if not azure_openai_client.is_configured:
        print("❌ WARNING: Azure OpenAI client is not configured. Chat API calls will fail.")
    else:
        print("✅ Azure OpenAI client appears configured.")
    print("--------------------------\n")
    app.run(debug=True)
