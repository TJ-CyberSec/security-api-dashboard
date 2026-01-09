import os
from dotenv import load_dotenv

load_dotenv()  # Loads .env

keys = {
    'VirusTotal': os.getenv('VIRUSTOTAL_API_KEY'),
    'AbuseIPDB': os.getenv('ABUSEIPDB_API_KEY'),
    'NVD': os.getenv('NVD_API_KEY')
}

for name, key in keys.items():
    status = "✅ Loaded" if key else "❌ Missing"
    print(f"{name}: {status} ({'Yes' if key else 'No'})")