> ⚠️ **LEGAL NOTICE:** This tool is for AUTHORIZED testing only. 
> Unauthorized use is ILLEGAL.

# 🔍 SQL Injection Vulnerability Scanner

A Python-based security testing tool that detects SQL injection vulnerabilities in web applications. Built for **ethical penetration testing** and security education.

## ⚠️ LEGAL & ETHICAL NOTICE

**READ THIS BEFORE USING:**

This tool is for **AUTHORIZED TESTING ONLY**. Unauthorized vulnerability scanning is:
- ❌ **ILLEGAL** in most jurisdictions
- ❌ **UNETHICAL** and violates computer fraud laws
- ❌ Can result in criminal prosecution

### ✅ Acceptable Use:
- Your own applications
- Applications where you have **written permission** to test
- Authorized testing environments (DVWA, intentionally vulnerable apps)
- Educational purposes in controlled environments

### ❌ Prohibited Use:
- Scanning websites without permission
- Testing production systems without authorization
- Any malicious or unauthorized testing

**By using this tool, you agree to use it ethically and legally.**

---

## 🌟 Features

### Detection Capabilities
- 🔍 **Error-Based Detection** - Identifies SQL errors in responses
- ⏱️ **Time-Based Detection** - Detects blind SQL injection via delays
- 🎯 **Multiple Database Support** - MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- 📝 **30+ Payloads** - Common SQL injection patterns

### Technical Features
- 🔄 **Concurrent Scanning** - Multi-threaded parameter testing
- ⏰ **Rate Limiting** - Configurable delays to avoid overwhelming servers
- 📊 **Detailed Reporting** - JSON output with vulnerability details
- 🛡️ **Ethical Safeguards** - Permission checks before scanning
- 📝 **Comprehensive Logging** - All activities logged for audit

### Supported Attack Types
- Union-based SQL injection
- Boolean-based blind SQL injection
- Time-based blind SQL injection
- Error-based SQL injection
- Authentication bypass
- Comment-based injection
- Stacked queries

---

## 📋 Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

---

## 🚀 Installation

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/sqli-scanner.git
cd sqli-scanner
```

### Step 2: Install Dependencies

```bash
pip install requests
```

Or use requirements.txt:

```bash
pip install -r requirements.txt
```

---

## 📖 Usage Guide

### Basic Syntax

```bash
python sqli_scanner.py -u <URL> -p <parameters> [options]
```

### Required Arguments

- `-u, --url` - Target URL to scan
- `-p, --parameters` - Comma-separated list of parameters to test

### Optional Arguments

- `-m, --method` - HTTP method: GET or POST (default: GET)
- `-d, --data` - POST data in format: key1=value1&key2=value2
- `-t, --threads` - Number of concurrent threads (default: 5)
- `--delay` - Delay between requests in seconds (default: 1.0)
- `--timeout` - Request timeout in seconds (default: 10)
- `-o, --output` - Output report file (default: sqli_report.json)
- `-v, --verbose` - Verbose output

---

## 💡 Examples

### Example 1: Scan DVWA (Local Testing)

```bash
python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id
```

### Example 2: Scan with Multiple Parameters

```bash
python sqli_scanner.py -u http://localhost/search.php -p query,category,sort
```

### Example 3: POST Request Testing

```bash
python sqli_scanner.py -u http://localhost/login.php -m POST -p username,password -d "username=admin&password=test"
```

### Example 4: Custom Threading and Delay

```bash
python sqli_scanner.py -u http://localhost/test.php -p id --threads 10 --delay 0.5
```

### Example 5: Verbose Output

```bash
python sqli_scanner.py -u http://localhost/page.php -p id -v
```

---

## 🎯 Recommended Test Targets

### Safe Testing Environments:

1. **DVWA (Damn Vulnerable Web Application)**
   ```bash
   # Install locally: https://github.com/digininja/DVWA
   python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id
   ```

2. **testphp.vulnweb.com** (Authorized Testing Site)
   ```bash
   python sqli_scanner.py -u http://testphp.vulnweb.com/artists.php -p artist
   ```

3. **bWAPP** (Buggy Web Application)
   ```bash
   # Install locally
   python sqli_scanner.py -u http://localhost/bWAPP/sqli_1.php -p title
   ```

4. **Your Own Local Applications**
   ```bash
   python sqli_scanner.py -u http://localhost/myapp/search.php -p q
   ```

---

## 📊 Output & Reports

### Console Output

```
============================================================
SQL INJECTION SCAN SUMMARY
============================================================
Target URL: http://localhost/dvwa/vulnerabilities/sqli/
Scan completed: 2024-01-30 15:30:45
Total vulnerabilities found: 1
============================================================

⚠️  VULNERABILITIES DETECTED:

1. Parameter: id
   Method: GET
   Payload: ' OR '1'='1
   Error: You have an error in your SQL syntax...

============================================================
```

### JSON Report (sqli_report.json)

```json
{
  "scan_info": {
    "target": "http://localhost/dvwa/vulnerabilities/sqli/",
    "timestamp": "2026-01-30T15:30:45.123456",
    "total_vulnerabilities": 1
  },
  "vulnerabilities": [
    {
      "url": "http://localhost/dvwa/vulnerabilities/sqli/",
      "parameter": "id",
      "payload": "' OR '1'='1",
      "method": "GET",
      "error_message": "You have an error in your SQL syntax...",
      "response_code": 200,
      "timestamp": "2026-01-30T15:30:45.123456"
    }
  ]
}
```

### Log File (sqli_scan_results.log)

```
2026-01-30 15:30:45,123 - INFO - Scanner initialized for: http://localhost/dvwa
2026-01-30 15:30:46,234 - INFO - Scanning parameter: id (GET)
2026-01-30 15:30:47,345 - WARNING - VULNERABILITY FOUND: id with payload: ' OR '1'='1
2026-01-30 15:30:48,456 - INFO - Report saved to: sqli_report.json
```

---

## 🔬 How It Works

### 1. Payload Injection

The scanner injects SQL payloads into target parameters:

```
Original URL: http://example.com/page.php?id=1
Injected URL: http://example.com/page.php?id=1' OR '1'='1
```

### 2. Error Detection

Scans responses for SQL error patterns:

```python
ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"PostgreSQL.*ERROR",
    r"ORA-[0-9][0-9][0-9][0-9]",
    # ... 20+ patterns
]
```

### 3. Time-Based Detection

Detects blind SQL injection by measuring response time:

```
Payload: ' OR SLEEP(5)--
Normal response time: <1 second
Vulnerable response time: >5 seconds
```

### 4. Result Classification

Vulnerabilities are classified by:
- Type (Error-based, Time-based, Boolean-based)
- Severity
- Affected parameter
- Successful payload

---

## 🛡️ Ethical Safeguards

### Built-in Safety Features:

1. **Target Verification**
   - Checks for localhost/testing environments
   - Warns user before scanning external sites
   - Requires explicit confirmation

2. **Rate Limiting**
   - Configurable delays between requests
   - Prevents overwhelming target servers
   - Default: 1 second between requests

3. **User Agent Identification**
   ```
   User-Agent: SQLi-Scanner/1.0 (Ethical Security Testing)
   ```

4. **Limited Payload Testing**
   - Stops testing parameter after first vulnerability
   - Prevents excessive exploitation

5. **Comprehensive Logging**
   - All activities logged with timestamps
   - Audit trail for responsible disclosure

---

## 🔧 Configuration

### Adjusting Concurrency

```bash
# Low impact (slower, safer)
python sqli_scanner.py -u URL -p param --threads 1 --delay 2.0

# Balanced (default)
python sqli_scanner.py -u URL -p param --threads 5 --delay 1.0

# Aggressive (faster, more load)
python sqli_scanner.py -u URL -p param --threads 10 --delay 0.5
```

### Custom Timeout

```bash
# For slow servers
python sqli_scanner.py -u URL -p param --timeout 30
```

---

## 🔍 Understanding Results

### Vulnerability Indicators

**Error-Based Injection:**
```
Error: You have an error in your SQL syntax
Status: HIGH RISK
Action: Immediate remediation required
```

**Time-Based Injection:**
```
Response Time: 5.2 seconds (expected: <1 second)
Status: HIGH RISK
Action: Investigate query structure
```

**No Vulnerability:**
```
Total vulnerabilities found: 0
Status: PASSED
Action: None (but consider additional testing)
```

---

## 📚 SQL Injection Types Explained

### 1. Classic SQL Injection

**Payload:** `' OR '1'='1`

**Attack:**
```sql
-- Original query
SELECT * FROM users WHERE id = '1'

-- Injected query
SELECT * FROM users WHERE id = '' OR '1'='1'
-- Returns all users!
```

### 2. Union-Based Injection

**Payload:** `' UNION SELECT NULL,NULL--`

**Attack:**
```sql
-- Original
SELECT name, email FROM users WHERE id = '1'

-- Injected
SELECT name, email FROM users WHERE id = '' 
UNION SELECT username, password FROM admin_users--
```

### 3. Time-Based Blind

**Payload:** `' OR SLEEP(5)--`

**Attack:**
```sql
-- If true, database sleeps 5 seconds
SELECT * FROM users WHERE id = '' OR SLEEP(5)--
```

---

## 🚨 Remediation Guidance

If vulnerabilities are found:

### 1. Use Parameterized Queries

**❌ Vulnerable:**
```python
query = f"SELECT * FROM users WHERE id = '{user_input}'"
```

**✅ Secure:**
```python
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_input,))
```

### 2. Use ORM Frameworks

```python
# Django ORM (secure by default)
User.objects.get(id=user_input)

# SQLAlchemy (parameterized)
session.query(User).filter(User.id == user_input)
```

### 3. Input Validation

```python
# Validate input type
if not user_input.isdigit():
    raise ValueError("Invalid input")

# Whitelist allowed values
allowed_values = ['1', '2', '3']
if user_input not in allowed_values:
    raise ValueError("Invalid input")
```

### 4. Escape Special Characters

```python
import re

# Remove or escape SQL special characters
safe_input = re.sub(r"[;'\"]", "", user_input)
```

---

## 🧪 Testing the Scanner

### Test on DVWA (Safe Environment)

1. **Install DVWA:**
   ```bash
   git clone https://github.com/digininja/DVWA.git
   # Follow DVWA installation instructions
   ```

2. **Set Security Level to Low:**
   - Login to DVWA
   - Go to Security → Set to "Low"

3. **Run Scanner:**
   ```bash
   python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id
   ```

4. **Expected Result:**
   ```
   Total vulnerabilities found: 1
   Parameter: id
   Payload: ' OR '1'='1
   ```

---

## 🔧 Troubleshooting

### Issue: "No vulnerabilities found" on known vulnerable target

**Solution:**
- Check if URL is correct
- Verify parameter names
- Ensure target is actually vulnerable
- Try different payloads manually first

---

### Issue: "Connection timeout"

**Solution:**
```bash
# Increase timeout
python sqli_scanner.py -u URL -p param --timeout 30
```

---

### Issue: "Too many requests" or rate limiting

**Solution:**
```bash
# Increase delay, reduce threads
python sqli_scanner.py -u URL -p param --threads 2 --delay 3.0
```

---

### Issue: False positives

**Solution:**
- Manually verify findings
- Check response differences
- Review error messages
- Test with safe input

---

## 📊 Performance Considerations

### Scan Times

| Parameters | Threads | Delay | Approx. Time |
|-----------|---------|-------|--------------|
| 1 param   | 5       | 1.0s  | ~30 seconds  |
| 3 params  | 5       | 1.0s  | ~90 seconds  |
| 5 params  | 10      | 0.5s  | ~75 seconds  |

### Resource Usage

- **CPU:** Low (mostly I/O bound)
- **Memory:** <50MB
- **Network:** Depends on delay/threads
- **Disk:** Minimal (logs and reports)

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add ethical use disclaimers to new features
4. Test thoroughly
5. Submit a pull request

---

## 📜 License

MIT License - See LICENSE file

**Disclaimer:** This tool is for educational and authorized testing only. The authors are not responsible for misuse.

---

## 🎓 Educational Resources

### Learn More About SQL Injection:

- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection)
- [HackerOne Hacking Tutorials](https://www.hacker101.com/)

### Practice Environments:

- DVWA (Damn Vulnerable Web Application)
- bWAPP (Buggy Web Application)
- WebGoat (OWASP)
- HackTheBox (Authorized Pentesting)

---

## ⚖️ Legal Compliance

This tool is designed to comply with:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar legislation worldwide

**Always ensure:**
- You have written authorization
- You're testing within scope
- You follow responsible disclosure
- You document your authorization

---

## 📧 Responsible Disclosure

If you find vulnerabilities:

1. **DO NOT** exploit beyond proof-of-concept
2. **DO** notify the website owner immediately
3. **DO** give them time to fix (30-90 days typical)
4. **DO** document findings professionally
5. **DO** follow coordinated disclosure practices

---

## 🏆 Best Practices

### For Security Testers:

✅ Always get written authorization
✅ Define scope clearly
✅ Use rate limiting
✅ Document everything
✅ Follow responsible disclosure
✅ Respect privacy and data

### For Developers:

✅ Use parameterized queries
✅ Implement input validation
✅ Use ORM frameworks
✅ Regular security testing
✅ Code reviews
✅ Security training for team

---

## 📝 Author

Created for educational purposes and ethical security testing.

**For Internship/Portfolio Use:**
- Demonstrates understanding of web vulnerabilities
- Shows secure coding practices
- Highlights ethical security mindset
- Professional tool development skills

---

**Remember: With great power comes great responsibility. Use this tool ethically!** 🔐
