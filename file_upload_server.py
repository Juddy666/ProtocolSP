from flask import Flask, request, jsonify, send_from_directory
import os
import uuid

app = Flask(__name__)

# Set the upload folder
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create the uploads directory if it doesn't exist

# File size limit (adjust as needed)
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if file:
        # Check if the file size is acceptable
        if len(file.read()) > MAX_FILE_SIZE:
            return jsonify({"error": "File too large"}), 413

        # Reset file stream after reading size
        file.seek(0)

        # Generate a unique filename and save the file
        unique_filename = str(uuid.uuid4()) + "_" + file.filename
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(file_path)

        # Return the file URL
        file_url = f"http://{request.host}/uploaded/{unique_filename}"
        return jsonify({"file_url": file_url}), 200
    
    return jsonify({"error": "File upload failed"}), 500

@app.route('/uploads/<filename>', methods=['GET'])
def get_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)
def index():
    return "Hello, Flask is working!" #debugging

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8088)  # Set the host and port as needed