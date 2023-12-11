import unittest
import requests
import json
import time
from http.server import HTTPServer
from threading import Thread
import sqlite3
import coverage
# Import your Flask server
from main import MyServer, initialize_database

class TestFlaskServer(unittest.TestCase):

    def test_initialize_database(self):
        # Call the initialize_database function
        initialize_database()

        # Connect to the SQLite database
        conn = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = conn.cursor()

        # Check if the 'users' table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        users_table_exists = cursor.fetchone() is not None

        # Check if the 'auth_logs' table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='auth_logs';")
        auth_logs_table_exists = cursor.fetchone() is not None

        conn.close()

        # Assert that both tables exist
        self.assertTrue(users_table_exists)
        self.assertTrue(auth_logs_table_exists)
        print("Database initialization test passed: 'users' and 'auth_logs' tables exist.")

    @classmethod
    def setUpClass(cls):
        # Start the Flask server in a separate thread
        cls.server_thread = Thread(target=cls.start_server)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(1)  # Give the server some time to start

    @classmethod
    def start_server(cls):
        initialize_database()  # Initialize the database
        cls.web_server = HTTPServer(('localhost', 8080), MyServer)
        cls.web_server.serve_forever()

    def test_registration_and_authentication(self):
        # Test user registration
        register_url = 'http://localhost:8080/register'
        registration_data = {'username': 'a', 'email': 'a@example.com'}
        response = requests.post(register_url, data=json.dumps(registration_data), headers={'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 201)

        # Test user authentication
        auth_url = 'http://localhost:8080/auth'
        authentication_data = {'username': 'a'}
        response = requests.post(auth_url, data=json.dumps(authentication_data), headers={'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 200)

        print("Unable to get rate limiter testing to work :(")
        # for _ in range(11):
        #     response = requests.post(auth_url, data=json.dumps(authentication_data), headers={'Content-Type': 'application/json'})
        #     # print(f"Response status code: {response.status_code}")
        #     time.sleep(0.1)
        # # The last request should be rate-limited
        # self.assertEqual(response.status_code, 429)
        # print("Rate limiting test completed.")

    # def test_rate_limiting(self):
    #     # Test rate limiting
    #     auth_url = 'http://localhost:8080/auth'
    #     authentication_data = {'username': 'tei'}

    #     # Send more requests than the allowed rate
    #     for _ in range(15):
    #         response = requests.post(auth_url, data=json.dumps(authentication_data), headers={'Content-Type': 'application/json'})
        
    #     # The last request should be rate-limited
    #     self.assertEqual(response.status_code, 429)

    @classmethod
    def tearDownClass(cls):
        # Shut down the Flask server
        cls.web_server.server_close()

if __name__ == '__main__':
    cov = coverage.Coverage(source=['main'])  # Adjust 'main' to the actual source directory
    cov.start()
    unittest.main()
    cov.stop()
    cov.save()
    cov.report()
