import os
import requests
from requests.auth import HTTPBasicAuth

# Load credentials from environment variables or config file
username = os.getenv('FARADAY_USER')
password = os.getenv('FARADAY_PASS')

if username is None or password is None:
    raise EnvironmentError("Faraday credentials not set in environment variables.")

# Example of sending a request to Faraday
url = 'http://faraday.example.com/api/'  # Replace with your Faraday API URL
response = requests.get(url, auth=HTTPBasicAuth(username, password))

if response.status_code == 200:
    print('Success:', response.json())
else:
    print('Error:', response.status_code, response.text)
