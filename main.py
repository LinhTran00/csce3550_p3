from flask import Flask, request, jsonify
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json
import sqlite3
import uuid
import os
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import time
import secrets
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta




hostName = "localhost"
serverPort = 8080
request_counts = {}
request_interval = 1  # Time window for rate limiting in seconds
max_requests = 10  # Maximum number of requests allowed in the time window

def initialize_database():
    # Connect to the SQLite database
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    # Create the users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    conn.commit()

    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    # Create the users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,  
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

# Initialize Argon2 password hasher
ph = PasswordHasher()

encryption_key = os.environ.get('ee06bb4dd5f54ba790560846b37ef5d3292662ca44302ada2d7279f776c150fe')

class TokenBucket:
    
    def __init__(self, capacity, fill_rate):
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.fill_rate = float(fill_rate)
        self.last_update = time.time()

    def consume(self, tokens):
        now = time.time()
        elapsed_time = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed_time * self.fill_rate)
        self.last_update = now

        if tokens <= self.tokens:
            self.tokens -= tokens
            return True
        else:
            return False
        
class MyServer(BaseHTTPRequestHandler):

    token_bucket = TokenBucket(10,1)

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return
    def log_message(self, format, *args):
        # Add logging to print messages to console
        print(f"Log Message: {format % args}")

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            return self.do_POST_auth()
        elif parsed_path.path == "/register":
            data_length = int(self.headers['Content-Length'])
            data = self.rfile.read(data_length)
            user_data = json.loads(data)

            # Generate a secure password using UUIDv4
            generated_password = str(uuid.uuid4())

            # Hash the password using Argon2 (using default settings)
            ph = PasswordHasher()
            hashed_password = ph.hash(generated_password)

            # Store user details and hashed password in the users table (SQLite)
            conn = sqlite3.connect('totally_not_my_privateKeys.db')
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE,
                    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP   
                )
            ''')
            conn.commit()

            cursor.execute('''
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
            ''', (user_data['username'], user_data.get('email'), hashed_password))
            
            conn.commit()
            conn.close()

            # Return the generated password to the user
            response_data = {'password': generated_password}
            self.send_response(201)  # HTTP status code CREATED
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response_data), "utf-8"))
            return
        else:
            self.send_response(405)
            self.end_headers()
            return

   
    def do_POST_auth(self):
        # Use the token bucket to check if the request is allowed
        if  not self.token_bucket.consume(1):
            self.send_response(429)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response_data = {'error': 'Rate limit exceeded'}
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            return
        data_length = int(self.headers['Content-Length'])
        data = self.rfile.read(data_length)
        auth_data = json.loads(data)

        # Authenticate user (you may want to add actual authentication logic here)

        # Log the details into the auth_logs table
        conn = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = conn.cursor()

        # Retrieve user_id based on the username
        cursor.execute('SELECT id FROM users WHERE username = ?', (auth_data['username'],))
        user_id = cursor.fetchone()

        if user_id:
            user_id = user_id[0]  # Extract the user_id from the tuple

            # Log the details into auth_logs table
            cursor.execute('''
                INSERT INTO auth_logs (request_ip, user_id)
                VALUES (?, ?)
            ''', (self.client_address[0], user_id))

            conn.commit()
            conn.close()

            # Return a response if needed
            response_data = {'message': 'Authentication successful'}
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response_data), "utf-8"))
        else:
            # Return an error response if user is not found
            response_data = {'error': 'User not found'}
            self.send_response(404)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response_data), "utf-8"))
            return

# Use the MyServer class as the HTTP server
if __name__ == "__main__":
    initialize_database()
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started on http://localhost:8080")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    
    webServer.server_close()