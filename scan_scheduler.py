import os
import requests
from requests.auth import HTTPBasicAuth

# Load credentials from environment variables
username = os.getenv('FARADAY_USERNAME')
password = os.getenv('FARADAY_PASSWORD')

# Example function that uses HTTP Basic Authentication

def make_request(url):
    response = requests.get(url, auth=HTTPBasicAuth(username, password))
    return response.json()
