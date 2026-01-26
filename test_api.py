import requests
import os
from dotenv import load_dotenv

load_dotenv()

# Test VirusTotal API
vt_key = os.getenv('VIRUSTOTAL_API_KEY')    #your actual API key string, Looks up the environment variable named VIRUSTOTAL_API_KEY and stores its value in the variable vt_key
test_ip = "8.8.8.8"  # Google's DNS
url = f"https://www.virustotal.com/api/v3/ip_addresses/{test_ip}"      #Creates the full API endpoint URL. The f-string inserts the test_ip value into the URL, so it becomes https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8

headers = {"x-apikey": vt_key}        #Creates a dictionary containing HTTP headers. VirusTotal requires your API key in a header named x-apikey for authentication.

response = requests.get(url, headers=headers)    #Sends an HTTP GET request to the URL with the specified headers. 

if response.status_code == 200:   #Checks if the request was successful, status code 200 means successful, 404 = not found
    print("✓ VirusTotal API is WORKING!")
    data = response.json()    #JSON is the standard format APIs use to send data. This converts the response from JSON format (a text format that looks like {"key": "value"}) into a Python dictionary
    print(f"IP: {test_ip}")
    print(f"Country: {data['data']['attributes'].get('country', 'Unknown')}")
else:
    print(f"✗ Error: {response.status_code}")