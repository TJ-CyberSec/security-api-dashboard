from flask import Flask, render_template, request   #render_templates loads and display html files, requests lets you access data submitted through forms
import requests    #Imports the requests library to make API calls to VirusTotal and AbuseIPDB.
import os     #Imports the os module to read environment variables (API keys)
from dotenv import load_dotenv   #Imports the function to load your .env file.

load_dotenv()            #Executes the function to read .env and load all your API keys into memory.
app = Flask(__name__)     #Creates your Flask web application object. __name__ is a special Python variable that tells Flask where to find templates and static files

#getting api keys
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')    #Gets your VirusTotal API key from environment variables and stores it in a variable for easy access throughout the file
ABUSE_API_KEY= os.getenv('ABUSEIPDB_API_KEY')

@app.route('/')    #it tells Flask "when someone visits the homepage (/), run the function below." 
def home():    #defining the function that runs when someone visits your home page
   return render_template('dashboard.html')   #Loads the dashboard.html file from the templates folder and sends it to the user's browser.

@app.route('/check-ip', methods=['POST'])    #Creates a new route at /check-ip. The methods=['POST'] means this only accepts POST requests (form submissions)
def check_ip():    #funtion that handles ip address checking
   ip_address = request.form.get('ip_address')    #request.form contains all the form data, and .get('ip_address') extracts the value from the input field named "ip_address"

   #Call AbuseIPBD API
   url = 'https://api.abuseipdb.com/api/v2/check'   #The AbuseIPDB API endpoint URL where we'll send our request
   headers = {'key': ABUSE_API_KEY, 'Accept': 'application/json'}   #Creates headers dictionary. AbuseIPDB requires your API key in a header called Key, and Accept: application/json tells the API to send data back in JSON format
   params = {'ipAddress': ip_address, 'maxAgeInDays': 90}   #ipAddress - the IP we want to check, maxAgeInDays - only look at reports from the last 90 days

   response = requests.get(url, headers=headers, params=params)   #Sends a GET request to AbuseIPDB
   if response.status_code == 200:   
     data = response.json()['data']   #Converts the JSON response to a Python dictionary and extracts the 'data' section (where the actual results are)
     result = {
       'type': 'ip',   #Labels this as an IP check (vs a hash check) so the template knows how to display it
       'input': ip_address,
       'abuse_score': data['abuseConfidenceScore'],   #Extracts the abuse confidence score from AbuseIPDB's response (0-100, where 100 = definitely malicious)
       'country': data.get('countryCode', 'Unknown'),
       'reports': data['totalReports'],
       'is_malicious': data['abuseConfidenceScore'] > 50   #Creates a True/False value
     }
   else:
      result = {'error': f'API ERROR: {response.status_code}'}   #Creates error message if failed to connect
   return render_template('dashboard.html', result=result)  #Loads the dashboard.html template again, but this time passes the result dictionary to it

@app.route('/check-hash', methods=['POST'])   #Creates another route for file hash checking, only accepts POST requests
def check_hash():
    file_hash = request.form.get('file_hash')    #Gets the file hash the user entered in the form
    
    # Call VirusTotal API
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'   #Builds the VirusTotal API URL. The f-string inserts the hash into the URL
    headers = {'x-apikey': VT_API_KEY}    #VirusTotal requires the API key in a header called x-apikey
    
    response = requests.get(url, headers=headers)   #Makes the API call to VirusTotal with authentication
    
    if response.status_code == 200:
        data = response.json()['data']['attributes']   #Extracts the attributes section from VirusTotal's response
        stats = data['last_analysis_stats']    #Gets the statistics from the most recent scan
        
        result = {
            'type': 'hash',
            'input': file_hash,
            'malicious': stats['malicious'],
            'suspicious': stats['suspicious'],
            'harmless': stats['harmless'],
            'total_scans': sum(stats.values()),   #Adds up all the values in stats dictionary to get total number of antivirus engines that scanned it
            'is_malicious': stats['malicious'] > 0
        }
        return render_template('dashboard.html', result=result)
    else:
       result = {'error': f'API Error: {response.status_code}'}   
       return render_template('dashboard.html', result=result)
    
if __name__ == '__main__':   #This is a Python idiom that means "only run the following code if this file is run directly (not imported)
   app.run(debug=True)

    #API workflow: User submits form → Python gets form data → Python calls API → API sends back results → Python organizes results → Python sends results to template → User sees results