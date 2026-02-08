# 🧪 SQL Injection Scanner - Testing Guide

Complete step-by-step guide to safely test your SQL injection scanner.

## ⚠️ CRITICAL: Ethical Testing Only

**NEVER test this tool on:**
- ❌ Websites you don't own
- ❌ Production systems without permission
- ❌ Any unauthorized target

**ONLY test on:**
- ✅ Your own local applications
- ✅ DVWA (Damn Vulnerable Web Application)
- ✅ Authorized testing sites
- ✅ Systems with written permission

---

## Prerequisites Checklist

- [ ] Python 3.7+ installed
- [ ] `requests` library installed
- [ ] DVWA or test environment set up
- [ ] Understanding of SQL injection basics

---

## Step 1: Installation

### 1.1: Install Dependencies

```bash
pip install requests
```

Verify:
```bash
python -c "import requests; print('✅ Requests installed!')"
```

---

## Step 2: Set Up DVWA (Recommended Test Target)

### Option A: Docker Installation (Easiest)

```bash
# Pull DVWA Docker image
docker pull vulnerables/web-dvwa

# Run DVWA
docker run -d -p 80:80 vulnerables/web-dvwa

# Access at: http://localhost
# Default login: admin / password
```

### Option B: Manual Installation

1. **Download DVWA:**
   ```bash
   git clone https://github.com/digininja/DVWA.git
   cd DVWA
   ```

2. **Install with XAMPP/WAMP/MAMP** (Windows/Mac)
   - Copy to htdocs folder
   - Create database
   - Follow DVWA setup wizard

3. **Configure DVWA:**
   - Login: admin / password
   - Go to: DVWA Security
   - Set security level: **Low**

---

## Step 3: Basic Scanner Test

### Test 3.1: Help Command

```bash
python sqli_scanner.py -h
```

**Expected Output:**
```
usage: sqli_scanner.py [-h] -u URL -p PARAMETERS ...

SQL Injection Vulnerability Scanner (Ethical Use Only)
```

**Verify:**
- ✅ Help menu displays
- ✅ All options listed
- ✅ No errors

---

### Test 3.2: Simple Scan on DVWA

```bash
python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id
```

**Expected Output:**
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
```

**Verify:**
- ✅ Scanner runs without errors
- ✅ Vulnerability found (DVWA is intentionally vulnerable)
- ✅ Error message captured
- ✅ Report file created

---

## Step 4: Test Different Parameters

### Test 4.1: Multiple Parameters

```bash
python sqli_scanner.py -u http://localhost/test.php -p id,name,category
```

**What to observe:**
- Scanner tests each parameter
- Progress messages for each
- Results for all parameters

---

### Test 4.2: POST Method Testing

```bash
python sqli_scanner.py -u http://localhost/login.php -m POST -p username,password -d "username=test&password=test"
```

**What to observe:**
- POST requests being sent
- Parameters tested in body
- Results logged correctly

---

## Step 5: Test Concurrency & Rate Limiting

### Test 5.1: Single Thread (Slow)

```bash
python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id --threads 1 --delay 2.0
```

**Expected:**
- Very slow scanning
- 2 second delay between each request
- Low server load

---

### Test 5.2: Multi-Thread (Fast)

```bash
python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id --threads 10 --delay 0.5
```

**Expected:**
- Faster scanning
- Multiple concurrent requests
- Higher server load

---

### Test 5.3: Monitor Scan Speed

```bash
# Time the scan
time python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id
```

**Note the duration** - useful for performance testing

---

## Step 6: Test Detection Capabilities

### Test 6.1: Error-Based Detection

**Setup:**
Create a vulnerable PHP script:

```php
<?php
// test_error.php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '$id'";
mysqli_query($conn, $query); // Intentionally vulnerable
?>
```

**Test:**
```bash
python sqli_scanner.py -u http://localhost/test_error.php -p id
```

**Expected:**
- Detects SQL syntax errors
- Identifies vulnerable parameter
- Logs error message

---

### Test 6.2: Time-Based Detection

**Setup:**
Create script with sleep:

```php
<?php
// test_time.php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '$id'";
// Vulnerable to time-based injection
?>
```

**Test:**
```bash
python sqli_scanner.py -u http://localhost/test_time.php -p id --timeout 15
```

**Expected:**
- Detects delayed responses (>5 seconds)
- Identifies time-based blind SQLi
- Reports response time

---

## Step 7: Test Output & Reporting

### Test 7.1: JSON Report

```bash
python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id -o my_report.json
```

**Check:**
1. File `my_report.json` created
2. Open and verify JSON structure:
   ```json
   {
     "scan_info": {...},
     "vulnerabilities": [...]
   }
   ```

---

### Test 7.2: Log File

```bash
# Run scan
python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id

# Check log
cat sqli_scan_results.log
```

**Expected log entries:**
```
2024-01-30 15:30:45 - INFO - Scanner initialized
2024-01-30 15:30:46 - INFO - Scanning parameter: id
2024-01-30 15:30:47 - WARNING - VULNERABILITY FOUND
```

---

## Step 8: Test Ethical Safeguards

### Test 8.1: External URL Warning

```bash
python sqli_scanner.py -u https://google.com -p q
```

**Expected:**
```
⚠️  WARNING: ETHICAL TESTING REQUIREMENT
============================================================
This scanner should ONLY be used on:
  • Your own applications
  • Applications you have written permission to test
  
Do you have permission to scan this target? (yes/no):
```

**Type:** `no`

**Expected:**
```
❌ Scan aborted - unauthorized target
```

---

### Test 8.2: Localhost Bypass

```bash
python sqli_scanner.py -u http://localhost/test.php -p id
```

**Expected:**
- No permission prompt
- Scan proceeds directly
- (localhost is considered safe)

---

## Step 9: Test Edge Cases

### Test 9.1: Invalid URL

```bash
python sqli_scanner.py -u not-a-url -p id
```

**Expected:**
- Error message
- Graceful failure
- No crash

---

### Test 9.2: No Parameters

```bash
python sqli_scanner.py -u http://localhost/test.php
```

**Expected:**
- Error: "required: -p/--parameters"
- Usage help displayed

---

### Test 9.3: Connection Timeout

```bash
python sqli_scanner.py -u http://192.168.1.999 -p id --timeout 2
```

**Expected:**
- Timeout errors logged
- Scanner continues
- No crash

---

## Step 10: Test Verbose Mode

```bash
python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id -v
```

**Expected:**
- Detailed debug messages
- Request/response info
- Payload testing details
- More verbose logging

---

## Step 11: Performance Testing

### Test 11.1: Rapid Sequential Scans

```bash
# Run 3 scans back-to-back
python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id
python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id
python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id
```

**Verify:**
- No crashes
- Consistent results
- Log files append (don't overwrite)

---

### Test 11.2: Large Parameter List

```bash
python sqli_scanner.py -u http://localhost/test.php -p id,name,email,category,sort,filter,page,limit,offset,search
```

**Expected:**
- All 10 parameters tested
- Takes longer
- No crashes or hangs

---

## Step 12: Test Custom Payloads

### Modify Scanner (Optional Test)

Edit `sqli_scanner.py` to add custom payload:

```python
SQL_PAYLOADS = [
    # ... existing payloads ...
    "' OR 'x'='x",  # Add your custom payload
]
```

**Test:**
```bash
python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id
```

**Verify:**
- Custom payload is tested
- Results logged

---

## Complete Testing Checklist

Mark each test as completed:

### Installation & Setup
- [ ] ✅ Python 3.7+ installed
- [ ] ✅ Requests library installed
- [ ] ✅ DVWA set up (or test environment)
- [ ] ✅ Scanner runs without errors

### Basic Functionality
- [ ] ✅ Help menu displays
- [ ] ✅ Simple scan works on DVWA
- [ ] ✅ Vulnerability detected
- [ ] ✅ Report generated

### Detection Capabilities
- [ ] ✅ Error-based detection works
- [ ] ✅ Time-based detection works
- [ ] ✅ Multiple databases supported
- [ ] ✅ Different payload types tested

### Advanced Features
- [ ] ✅ Multiple parameters scan
- [ ] ✅ POST method works
- [ ] ✅ Concurrency works
- [ ] ✅ Rate limiting works
- [ ] ✅ Custom threads/delay

### Output & Reporting
- [ ] ✅ JSON report created
- [ ] ✅ Log file generated
- [ ] ✅ Console output clear
- [ ] ✅ Custom output path works

### Ethical Safeguards
- [ ] ✅ External URL warning works
- [ ] ✅ Localhost bypass works
- [ ] ✅ Permission prompt functional
- [ ] ✅ User can cancel scan

### Error Handling
- [ ] ✅ Invalid URL handled
- [ ] ✅ Connection timeout handled
- [ ] ✅ No crash on errors
- [ ] ✅ Graceful failures

### Edge Cases
- [ ] ✅ No parameters error
- [ ] ✅ Rapid scans work
- [ ] ✅ Large parameter lists
- [ ] ✅ Verbose mode works

---

## Troubleshooting Common Issues

### ❌ Issue: "ModuleNotFoundError: requests"

**Solution:**
```bash
pip install requests
```

---

### ❌ Issue: DVWA "Setup failed"

**Solution:**
1. Check database connection
2. Verify PHP installed
3. Follow DVWA setup wizard
4. Reset database if needed

---

### ❌ Issue: "No vulnerabilities found" on DVWA

**Solution:**
1. Check DVWA security level = Low
2. Verify you're logged in
3. Check correct URL
4. Test manually first

---

### ❌ Issue: "Connection refused"

**Solution:**
1. Verify server is running
2. Check port number
3. Test URL in browser
4. Check firewall settings

---

### ❌ Issue: Scanner hangs

**Solution:**
1. Press Ctrl+C to stop
2. Reduce --timeout value
3. Reduce --threads
4. Check network connection

---

## Screenshots for Report

Take these screenshots:

1. ✅ Scanner help menu
2. ✅ Successful scan on DVWA
3. ✅ Vulnerability detected output
4. ✅ JSON report contents
5. ✅ Log file contents
6. ✅ Permission warning dialog
7. ✅ Multiple parameters scan
8. ✅ Verbose output example

---

## Sample Test Results

### DVWA Low Security (Expected)
```
Total vulnerabilities found: 1
Parameter: id
Status: VULNERABLE ⚠️
```

### DVWA High Security (Expected)
```
Total vulnerabilities found: 0
Parameter: id
Status: SECURE ✅
```

### Production Site (Should Not Test!)
```
⚠️  WARNING: ETHICAL TESTING REQUIREMENT
❌ Scan aborted
```

---

## Performance Benchmarks

### Typical Scan Times

| Target | Parameters | Threads | Time |
|--------|-----------|---------|------|
| DVWA   | 1         | 5       | ~30s |
| DVWA   | 3         | 5       | ~90s |
| Local  | 5         | 10      | ~60s |

---

## What to Document

For your internship report:

1. **Test Environment Setup**
   - DVWA installation
   - Configuration steps

2. **Testing Process**
   - All test scenarios
   - Results observed

3. **Findings**
   - Vulnerabilities detected
   - False positives/negatives

4. **Performance**
   - Scan times
   - Resource usage

5. **Ethical Considerations**
   - Safeguards tested
   - Permission verification

---

## Advanced Testing (Optional)

### Test Against Different Databases

1. **MySQL (DVWA)**
2. **PostgreSQL** (set up test app)
3. **MSSQL** (set up test app)
4. **SQLite** (simple test app)

### Test Different Injection Types

1. **Union-based**
2. **Boolean-based**
3. **Time-based**
4. **Error-based**
5. **Stacked queries**

---

## Final Verification

Before considering testing complete:

```bash
# Run comprehensive test
python sqli_scanner.py -u http://localhost/dvwa/vulnerabilities/sqli/ -p id -v -o final_report.json

# Verify all outputs:
ls -la sqli_scan_results.log  # Log exists
ls -la final_report.json       # Report exists
cat final_report.json          # Valid JSON
```

**If all files exist and contain data:** ✅ Testing Complete!

---

## Safety Reminder

After testing:

1. ✅ Stop DVWA/test servers
2. ✅ Delete test databases
3. ✅ Never use on production
4. ✅ Document everything
5. ✅ Follow responsible disclosure

---

**Congratulations!** If all tests pass, your SQL injection scanner is working perfectly! 🎉

This demonstrates:
- Web security knowledge ✅
- HTTP request handling ✅
- Pattern matching ✅
- Concurrent programming ✅
- Ethical hacking principles ✅

Perfect for your internship portfolio! 🚀
