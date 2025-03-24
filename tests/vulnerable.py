import sqlite3
import os
import subprocess
import pickle
from flask import Flask, request

app = Flask(__name__)

# SQL Injection Vulnerability
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

# Command Injection Vulnerability
@app.route('/ping')
def ping_host():
    host = request.args.get('host', '')
    # Vulnerable command execution
    result = os.system(f"ping -c 1 {host}")
    return f"Ping result: {result}"

# Path Traversal Vulnerability
@app.route('/download')
def download_file():
    filename = request.args.get('file', '')
    # Vulnerable file access
    with open(filename, 'r') as f:
        return f.read()

# Insecure Deserialization
@app.route('/load_data')
def load_data():
    data = request.args.get('data', '')
    # Vulnerable deserialization
    return pickle.loads(data.encode())

# Hard-coded Credentials
def connect_to_database():
    username = "admin"
    password = "super_secret_password123"
    conn = sqlite3.connect('users.db', username=username, password=password)
    return conn

# Shell Injection
@app.route('/execute')
def execute_command():
    cmd = request.args.get('cmd', '')
    # Vulnerable shell command execution
    output = subprocess.check_output(cmd, shell=True)
    return output

# XSS Vulnerability
@app.route('/profile')
def show_profile():
    name = request.args.get('name', '')
    # Vulnerable XSS
    return f"<h1>Welcome, {name}!</h1>"

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode enabled in production 