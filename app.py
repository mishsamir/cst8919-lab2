from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

# Configure logging to console (stdout)
logging.basicConfig(level=logging.INFO)

USERNAME = "admin"
PASSWORD = "password123"

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    ip = request.remote_addr

    if username == USERNAME and password == PASSWORD:
        logging.info(f"SUCCESSFUL login from {ip} with username: {username}")
        return jsonify({"message": "Login successful!"}), 200
    else:
        logging.warning(f"FAILED login from {ip} with username: {username}")
        return jsonify({"message": "Invalid credentials"}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
