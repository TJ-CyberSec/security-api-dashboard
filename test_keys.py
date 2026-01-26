import os # Imports the 'os' module - lets us interact with operating system (read environment variables)
from dotenv import load_dotenv # Imports load_dotenv - this reads our .env file and loads the API keys into memory
from pathlib import Path # Imports Path - helps us work with file paths (find where .env file is)

# Prints where we are currently running the script from
print(f"Current directory: {os.getcwd()}") #get CurrentWorkingDirectory, this function tells which folder on the computer the python script is running from
print(f"Looking for .env at: {Path('.env').absolute()}") #Creates a path object pointing to a file named .env in the current directory, absolute converts the relative path to Full path

# Check if .env exists
env_path = Path('.env') #creates a path object representing the .env file and stores it in the variable 'env_path', 
if env_path.exists():
    print(f"✓ .env file found!")
    print(f"File size: {env_path.stat().st_size} bytes")
else:
    print("✗ .env file NOT found!")

# Load .env
load_dotenv() #reads the .env file and loads all the KEY=VALUE pairs into environment variables that your program can access

# Test keys
keys = {                       #creates a dictionary 'key'(a collection of name-value pairs), os.getenv() looks up the variable name and returns its value
    'VirusTotal': os.getenv('VIRUSTOTAL_API_KEY'),
    'AbuseIPDB': os.getenv('ABUSEIPDB_API_KEY'),
    'NVD': os.getenv('NVD_API_KEY')
}

print("\n=== Key Check ===")
for name, key in keys.items():        #creates 'name and 'key' on the fly by the for loop followed by tuple unpacking, .items() gives pairs: ('VirusTotal', 'abc123...') for loop takes each pair and unpacks it into 2 variables, first item to 'name' and second to 'key'. 
    if key:
        print(f"{name}: ✓ Loaded ('{key[:5]}...' - {len(key)} chars)")
    else:
        print(f"{name}: ✗ Missing (No)")