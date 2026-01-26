# 🛡️ Threat Intelligence Dashboard

A real-time security analysis tool that checks IP addresses and file hashes against threat intelligence databases to identify potential security threats.

![Dashboard Preview](screenshot.png)

## 🎯 Project Overview

This web application integrates with VirusTotal and AbuseIPDB APIs to provide instant threat assessment for:
- **IP Address Analysis** - Identifies malicious IPs, abuse scores, and geographic data
- **File Hash Verification** - Checks SHA-256 hashes against 70+ antivirus engines

Built as part of my cybersecurity portfolio to demonstrate API integration, web development, and security analysis skills.

## 🚀 Features

- ✅ Real-time threat intelligence lookup
- ✅ Integration with industry-standard APIs (VirusTotal, AbuseIPDB)
- ✅ Color-coded risk assessment (Safe/Malicious)
- ✅ Detailed analysis results with multiple data points
- ✅ Clean, professional web interface
- ✅ Secure API key management with environment variables

## 🛠️ Technologies Used

- **Backend**: Python 3.9+, Flask
- **APIs**: VirusTotal API v3, AbuseIPDB API v2
- **Frontend**: HTML5, CSS3, Jinja2 templating
- **Security**: python-dotenv for environment variable management

## 📦 Installation

### Prerequisites
- Python 3.9 or higher
- VirusTotal API key ([Get here](https://www.virustotal.com/gui/join-us))
- AbuseIPDB API key ([Get here](https://www.abuseipdb.com/register))

### Setup Steps

1. **Clone the repository**
```bash
git clone https://github.com/TJ-CyberSec/security-api-dashboard.git
cd security-api-dashboard
```

2. **Create virtual environment**
```bash
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Mac/Linux
```

3. **Install dependencies**
```bash
pip install flask requests python-dotenv
```

4. **Configure API keys**

Create a `.env` file in the project root:
```
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

5. **Run the application**
```bash
python app.py
```

6. **Access the dashboard**

Open your browser to: `http://127.0.0.1:5000/`

## 💡 Usage Examples

### Check an IP Address
1. Enter an IP address (e.g., `8.8.8.8`)
2. Click "Check IP"
3. View results: abuse score, country, total reports, and threat status

### Check a File Hash
1. Enter a SHA-256 hash
2. Click "Check Hash"
3. View results: malicious detections, suspicious flags, and overall status

**Example malicious hash (EICAR test file):**
```
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

## 📁 Project Structure
```
security-api-dashboard/
├── app.py                 # Main Flask application
├── templates/
│   └── dashboard.html     # Web interface
├── static/
│   └── style.css         # Styling
├── .env                  # API keys (not in repo)
├── .gitignore           # Git ignore rules
└── README.md            # This file
```

## 🔒 Security Considerations

- API keys stored in `.env` file (excluded from version control)
- Input validation on all user submissions
- Rate limiting awareness for API calls
- No sensitive data logged or stored

## 🎓 Learning Outcomes

Through this project, I gained hands-on experience with:
- RESTful API integration and authentication
- Flask web framework and routing
- Environment variable management for security
- HTML/CSS responsive design
- Error handling and user feedback
- Git version control and documentation

## 🚧 Future Enhancements

- [ ] Add batch IP/hash scanning from CSV files
- [ ] Implement result export (PDF/JSON)
- [ ] Add historical search tracking
- [ ] Integrate additional threat intelligence sources
- [ ] Add domain reputation checking
- [ ] Implement caching to reduce API calls

## 👤 Author

**Tejaswi (TJ) Thapa**
- Computer Science Student (Cybersecurity Focus)
- Location: Chattanooga, TN
- GitHub: [@TJ-CyberSec](https://github.com/TJ-CyberSec)
- Portfolio: Building projects for cybersecurity internship applications

## 📄 License

This project is open source and available for educational purposes.

## 🙏 Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for threat intelligence API
- [AbuseIPDB](https://www.abuseipdb.com/) for IP reputation data
- Flask documentation and community

---

*Built as part of a 4-week cybersecurity portfolio development plan*