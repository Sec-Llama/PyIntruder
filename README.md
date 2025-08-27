# PyIntruder Pro

<div align="center">

![PyIntruder Pro](https://img.shields.io/badge/PyIntruder-Pro%20v2.0.0-red?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.7+-green?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=for-the-badge)

**Advanced Web Security Testing & Analysis Tool**

*A sophisticated Burp Intruder alternative with intelligent response analysis and vulnerability detection*

</div>

---

##  Overview

PyIntruder Pro is a next-generation web application security testing tool designed for penetration testers, bug bounty hunters, and security researchers. It combines the power of automated fuzzing with intelligent analysis capabilities to identify security vulnerabilities with minimal false positives.

###  Key Features

- 🎯 **Smart Payload Injection** - Multiple injection strategies including manual parameters, marker-based (§), and auto-detection
- 🧠 **Intelligent Analysis** - Advanced response clustering and anomaly detection
- 🔍 **Vulnerability Detection** - Automated detection of authentication bypasses, user enumeration, and error disclosure
- ⚡ **High Performance** - Asynchronous architecture with configurable threading
- 📊 **Detailed Reporting** - Comprehensive JSON reports with security insights
- 🎨 **Professional Interface** - Colored output with progress tracking
- 🔧 **Burp Integration** - Direct import of Burp Suite request files

##  Installation

### Requirements
- Python 3.7+
- Dependencies: `aiohttp`, `aiofiles`, `colorama`

### Quick Install
```bash
git clone https://github.com/sec-llama/pyintruder-pro.git
cd pyintruder-pro
pip install -r requirements.txt
```

### Manual Dependencies
```bash
pip install aiohttp aiofiles colorama
```

##  Usage Examples

### 1. Manual Parameter Specification (Recommended)
```bash
# Single parameter fuzzing
python pyintruder.py -r request.txt -w usernames.txt --parameters "username:FUZZ"

# Multi-parameter testing
python pyintruder.py -r request.txt -w payloads.txt --parameters "username:FUZZ,password:admin123"

# Advanced context specification
python pyintruder.py -r request.txt -w xss.txt --parameters "url:search:FUZZ,header:X-Forwarded-For:FUZZ"
```

### 2. Marker-Based Injection
Add `§` markers in your request file:
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=§admin§&password=password123
```

Then run:
```bash
python pyintruder.py -r request.txt -w usernames.txt
```

### 3. Auto-Detection Mode
```bash
# Automatically find and fuzz all parameters
python pyintruder.py -r request.txt -w payloads.txt --auto-detect

# Target specific existing parameter
python pyintruder.py -r request.txt -w passwords.txt --target-param password
```

### 4. Advanced Configuration
```bash
python pyintruder.py -r request.txt -w huge-wordlist.txt \
  --parameters "user:FUZZ,pass:admin" \
  --threads 50 \
  --delay 0.1 \
  --timeout 15 \
  --output detailed_report.json
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-r, --request` | Request file (from Burp Suite) | Required |
| `-w, --wordlist` | Wordlist file with payloads | Required |
| `--parameters` | Manual parameter specification | None |
| `--auto-detect` | Auto-detect injection points | False |
| `--target-param` | Target specific parameter | None |
| `-t, --threads` | Concurrent threads | 10 |
| `-d, --delay` | Delay between requests (seconds) | 0 |
| `--timeout` | Request timeout (seconds) | 10 |
| `-o, --output` | JSON report output file | None |
| `--show-all` | Show all responses | False |

##  Parameter Specification Formats

### Context Types
- `url:param:value` - URL parameters
- `body:param:value` - POST body parameters  
- `header:name:value` - HTTP headers

### Value Types
- `FUZZ` or `WORDLIST` - Use wordlist payloads
- `fixed_value` - Use static value
- Empty - Use wordlist (default)

### Examples
```bash
# URL parameter fuzzing
--parameters "url:id:FUZZ"

# Form data with mixed values
--parameters "body:username:FUZZ,body:password:admin123"

# Header injection
--parameters "header:User-Agent:FUZZ,header:X-Real-IP:127.0.0.1"

# Mixed contexts
--parameters "url:callback:FUZZ,body:csrf_token:abc123,header:Authorization:Bearer FUZZ"
```

##  Advanced Analysis Features

### Vulnerability Detection
- **Authentication Bypass** - Identifies responses that differ from expected patterns
- **User Enumeration** - Timing-based, response-based, and error-based detection
- **Information Disclosure** - Automatic detection of error messages and stack traces
- **Response Clustering** - Groups similar responses to identify anomalies

### Error Pattern Recognition
- SQL injection errors (MySQL, PostgreSQL, Oracle, SQLite)
- Path disclosure vulnerabilities
- Stack trace leakage
- Server configuration errors
- Application-specific error messages

##  Output & Reporting

### Console Output
```
[INFO] Loading request template from login.txt
[SUCCESS] Parsed POST request to target.com
[SUCCESS] Loaded 1000 payloads
Fuzzing body.username with 1000 payloads...
Progress [1/1]: 100.0% (1000/1000) ✓ body.username

POTENTIAL VULNERABILITIES DETECTED:
[VULN] User Enumeration (Response Based): 3 instances
   Sample payloads: admin, administrator, root

INTERESTING RESPONSES (15):
   Status 200, Length 1247: 12 responses (e.g., 'admin')
   Status 500, Length 0: 3 responses (e.g., 'admin"')
```

### JSON Report Structure
```json
{
  "scan_info": {
    "timestamp": "2024-01-15 14:30:22",
    "tool": "PyIntruder Pro v2.0.0",
    "total_requests": 1000
  },
  "analysis_summary": {
    "potential_vulnerabilities": [...],
    "interesting_responses": [...],
    "unique_response_patterns": 45
  },
  "detailed_results": [...]
}
```

##  Use Cases

### Bug Bounty Hunting
- Parameter discovery and fuzzing
- Authentication bypass testing
- User enumeration attacks
- Input validation testing

### Penetration Testing
- Login brute forcing with intelligent analysis
- Parameter pollution testing
- Error-based information gathering
- Response time analysis

### Security Research
- Custom payload testing
- Protocol fuzzing
- Response pattern analysis
- Vulnerability validation

## ⚠️ Responsible Disclosure

This tool is designed for authorized security testing only. Users are responsible for:
- Obtaining proper authorization before testing
- Following responsible disclosure practices
- Complying with applicable laws and regulations
- Using the tool ethically and professionally

##  Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) and submit pull requests for:
- New vulnerability detection modules
- Performance improvements
- Additional payload injection techniques
- Documentation improvements

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Acknowledgments

- Inspired by PortSwigger's Burp Suite Intruder
- Built with modern Python async/await patterns
- Incorporates industry-standard security testing methodologies

---

<div align="center">

**Made with ❤️ for the security community**

[![GitHub stars](https://img.shields.io/github/stars/sec-llama/pyintruder-pro?style=social)](https://github.com/yourusername/pyintruder-pro/stargazers)

</div>

##  Quick Start Guide

### 1. Export Request from Burp
1. Right-click request in Burp Suite
2. "Copy to file" or "Save item"
3. Save as `request.txt`

### 2. Prepare Wordlist
```bash
# Download common usernames
wget https://github.com/danielmiessler/SecLists/raw/master/Usernames/top-usernames-shortlist.txt

# Or create custom wordlist
echo -e "admin\nadministrator\nroot\ntest\nguest" > usernames.txt
```

### 3. Run Attack
```bash
# Basic username enumeration
python pyintruder.py -r request.txt -w usernames.txt --parameters "username:FUZZ"

# Advanced multi-parameter testing
python pyintruder.py -r request.txt -w passwords.txt \
  --parameters "user:admin,pass:FUZZ" \
  --threads 20 --output report.json
```

### 4. Analyze Results
- Review console output for immediate findings
- Check JSON report for detailed analysis
- Look for response clustering and anomalies
- Investigate potential vulnerabilities flagged

---

*For detailed documentation, advanced usage examples, and troubleshooting, visit our [Wiki](https://github.com/yourusername/pyintruder-pro/wiki).*
