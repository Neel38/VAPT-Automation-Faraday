import os
import requests
from requests.auth import HTTPBasicAuth

FARADAY_USERNAME = os.getenv('FARADAY_USERNAME')
FARADAY_PASSWORD = os.getenv('FARADAY_PASSWORD')

# Sample request using the username and password for authentication
url = 'http://your-faraday-instance/api/endpoint'
response = requests.get(url, auth=HTTPBasicAuth(FARADAY_USERNAME, FARADAY_PASSWORD))

if response.status_code == 200:
    print('Success:', response.json())
else:
    print('Failed with status code:', response.status_code)