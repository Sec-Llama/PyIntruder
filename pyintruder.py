#!/usr/bin/env python3
"""
PyIntruder Pro - Advanced Web Security Testing Tool
A sophisticated Burp Intruder-like tool with intelligent response analysis.
Author: Elite Security Research Team
Version: 2.0.0
"""

import argparse
import asyncio
import aiohttp
import aiofiles
import re
import sys
import time
import json
import urllib.parse
import hashlib
import statistics
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
from collections import Counter, defaultdict
import logging
from colorama import Fore, Back, Style, init
from urllib.parse import urlencode, parse_qs
import difflib

# Initialize colorama for cross-platform colored output
init(autoreset=True)

@dataclass
class RequestTemplate:
    """Represents a parsed HTTP request template."""
    method: str
    path: str
    headers: Dict[str, str]
    body: str = ""
    host: str = ""
    scheme: str = "https"
    
@dataclass 
class PayloadPosition:
    """Represents a payload insertion position in the request."""
    start: int
    end: int
    param_name: str = ""
    position_type: str = "url"  # url, body, header
    
@dataclass
class AttackResult:
    """Represents the result of a single attack request."""
    payload: str
    status_code: int
    response_length: int
    response_time: float
    response_body: str = ""
    response_hash: str = ""
    error: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    redirect_location: str = ""
    content_type: str = ""
    server_header: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)

class ColorLogger:
    """Professional colored logging for security tools."""
    
    @staticmethod
    def banner():
        print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                      PyIntruder Pro v2.0.0                  ║
║         Advanced Web Security Testing & Analysis Tool       ║
║                  For Authorized Testing Only                ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """)
    
    @staticmethod
    def info(msg: str):
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def success(msg: str):
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def warning(msg: str):
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def error(msg: str):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def critical(msg: str):
        print(f"{Fore.WHITE}{Back.RED}[CRITICAL]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def vuln(msg: str):
        print(f"{Fore.WHITE}{Back.MAGENTA}[VULN]{Style.RESET_ALL} {msg}")

class RequestParser:
    """Enhanced request parser with parameter extraction."""
    
    @staticmethod
    def parse_burp_request(file_path: str) -> RequestTemplate:
        """Parse a request file saved from Burp Suite."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.strip().split('\n')
            if not lines:
                raise ValueError("Empty request file")
            
            # Parse request line
            request_line = lines[0].strip()
            method, path, protocol = request_line.split(' ', 2)
            
            # Parse headers
            headers = {}
            body_start = len(lines)
            
            for i, line in enumerate(lines[1:], 1):
                if line.strip() == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Extract host and determine scheme
            host = headers.get('Host', '')
            scheme = 'https' if '443' in host or 'https' in content.lower() else 'http'
            
            # Parse body
            body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
            
            return RequestTemplate(
                method=method,
                path=path,
                headers=headers,
                body=body,
                host=host,
                scheme=scheme
            )
            
        except Exception as e:
            ColorLogger.error(f"Failed to parse request file: {e}")
            sys.exit(1)
    
    @staticmethod
    def extract_parameters(request: RequestTemplate) -> Dict[str, List[str]]:
        """Extract all parameters from URL and body."""
        params = {"url": [], "body": [], "headers": []}
        
        # URL parameters
        if '?' in request.path:
            query_string = request.path.split('?', 1)[1]
            url_params = parse_qs(query_string)
            params["url"] = list(url_params.keys())
        
        # Body parameters (for POST requests)
        if request.body:
            if 'application/x-www-form-urlencoded' in request.headers.get('Content-Type', ''):
                body_params = parse_qs(request.body)
                params["body"] = list(body_params.keys())
            elif 'application/json' in request.headers.get('Content-Type', ''):
                try:
                    json_data = json.loads(request.body)
                    if isinstance(json_data, dict):
                        params["body"] = list(json_data.keys())
                except:
                    pass
        
        # Common injectable headers
        injectable_headers = ['User-Agent', 'X-Forwarded-For', 'X-Real-IP', 'Authorization']
        for header in injectable_headers:
            if header in request.headers:
                params["headers"].append(header)
        
        return params

class PayloadManager:
    """Advanced payload management with intelligent positioning."""
    
    PAYLOAD_MARKERS = ('§', '§')  # Burp-style markers
    
    @classmethod
    def find_payload_positions(cls, text: str, context_type: str = "url") -> List[PayloadPosition]:
        """Find all payload positions marked with § symbols."""
        positions = []
        pattern = r'§([^§]*)§'
        
        for match in re.finditer(pattern, text):
            positions.append(PayloadPosition(
                start=match.start(),
                end=match.end(),
                param_name=match.group(1) if match.group(1) else f"param_{len(positions)}",
                position_type=context_type
            ))
        
        return positions
    
    @classmethod
    def auto_detect_injection_points(cls, request: RequestTemplate) -> List[Tuple[str, str, str]]:
        """Automatically detect potential injection points."""
        injection_points = []
        
        # URL parameters
        if '?' in request.path:
            base_path, query_string = request.path.split('?', 1)
            url_params = parse_qs(query_string)
            for param in url_params:
                injection_points.append(("url", param, url_params[param][0]))
        
        # Body parameters
        if request.body and 'application/x-www-form-urlencoded' in request.headers.get('Content-Type', ''):
            body_params = parse_qs(request.body)
            for param in body_params:
                injection_points.append(("body", param, body_params[param][0]))
        
        return injection_points
    
    @staticmethod
    def load_wordlist(file_path: str) -> List[str]:
        """Load payloads from wordlist file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            ColorLogger.error(f"Failed to load wordlist {file_path}: {e}")
            return []
    
    @classmethod
    def inject_payload_smart(cls, request: RequestTemplate, injection_point: Tuple[str, str, str], payload: str) -> RequestTemplate:
        """Smart payload injection based on parameter type."""
        context, param_name, original_value = injection_point
        new_request = RequestTemplate(
            method=request.method,
            path=request.path,
            headers=request.headers.copy(),
            body=request.body,
            host=request.host,
            scheme=request.scheme
        )
        
        if context == "url":
            # URL parameter injection
            if '?' in new_request.path:
                base_path, query_string = new_request.path.split('?', 1)
                params = parse_qs(query_string)
                params[param_name] = [payload]
                new_request.path = base_path + '?' + urlencode(params, doseq=True)
            else:
                # Add parameter to URL if it doesn't exist
                new_request.path += f'?{param_name}={urllib.parse.quote(payload)}'
        
        elif context == "body":
            # Body parameter injection
            if 'application/x-www-form-urlencoded' in request.headers.get('Content-Type', ''):
                if new_request.body:
                    params = parse_qs(new_request.body)
                    params[param_name] = [payload]
                    new_request.body = urlencode(params, doseq=True)
                else:
                    # Create new form data
                    new_request.body = urlencode({param_name: payload})
            elif 'application/json' in request.headers.get('Content-Type', ''):
                # JSON parameter injection
                try:
                    if new_request.body:
                        json_data = json.loads(new_request.body)
                    else:
                        json_data = {}
                    json_data[param_name] = payload
                    new_request.body = json.dumps(json_data)
                except:
                    # Fallback to simple JSON
                    new_request.body = json.dumps({param_name: payload})
        
        elif context == "header":
            # Header injection
            new_request.headers[param_name] = payload
        
        elif context == "marker":
            # Marker-based injection (§ symbols)
            new_request.path = cls.inject_payload(new_request.path, 
                cls.find_payload_positions(new_request.path, "url"), [payload])
            new_request.body = cls.inject_payload(new_request.body,
                cls.find_payload_positions(new_request.body, "body"), [payload])
        
        return new_request
    
    @classmethod
    def parse_manual_parameters(cls, param_string: str) -> List[Tuple[str, str, str]]:
        """Parse manual parameter specification: 'username:admin,password:FUZZ,header:User-Agent:FUZZ'"""
        injection_points = []
        
        if not param_string:
            return injection_points
        
        # Split by comma for multiple parameters
        param_specs = [spec.strip() for spec in param_string.split(',')]
        
        for spec in param_specs:
            parts = spec.split(':')
            
            if len(parts) == 2:
                # Simple format: param_name:value_or_FUZZ
                param_name, value = parts
                if '=' in param_name:
                    # URL parameter format: param=value
                    param_name = param_name.split('=')[0]
                injection_points.append(("body", param_name, value))
                
            elif len(parts) == 3:
                # Extended format: context:param_name:value_or_FUZZ
                context, param_name, value = parts
                if context.lower() in ['url', 'body', 'header']:
                    injection_points.append((context.lower(), param_name, value))
                else:
                    # Treat first part as parameter name
                    injection_points.append(("body", f"{context}:{param_name}", value))
            
            elif len(parts) == 1:
                # Just parameter name, assume body context
                param_name = parts[0]
                injection_points.append(("body", param_name, "FUZZ"))
        
        return injection_points

class AdvancedAnalyzer:
    """Advanced response analysis for detecting security vulnerabilities."""
    
    def __init__(self):
        self.baseline_responses = []
        self.response_clusters = defaultdict(list)
        
    def calculate_response_hash(self, response_body: str) -> str:
        """Calculate hash of response content for similarity detection."""
        # Remove dynamic content like timestamps, session IDs, etc.
        cleaned = re.sub(r'\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}|[a-fA-F0-9]{32}|[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}', '', response_body)
        return hashlib.md5(cleaned.encode()).hexdigest()
    
    def detect_error_messages(self, response_body: str) -> List[str]:
        """Detect various types of error messages in responses."""
        error_patterns = [
            # SQL errors
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"ORA-\d+",
            r"PostgreSQL.*ERROR",
            r"SQLite.*error",
            
            # Path disclosure
            r"[A-Z]:\\[^<>\s\"]+|\/[^<>\s\"]*\/[^<>\s\"]*",
            
            # Stack traces
            r"at\s+[\w.$]+\([^)]*\)",
            r"Traceback \(most recent call last\)",
            
            # Server errors
            r"Internal Server Error",
            r"500 - Internal server error",
            r"Exception.*:",
            r"Fatal error:",
            
            # Application-specific errors
            r"Warning: Cannot modify header information",
            r"Notice: Undefined (variable|index)",
            r"Parse error: syntax error",
        ]
        
        found_errors = []
        for pattern in error_patterns:
            matches = re.findall(pattern, response_body, re.IGNORECASE)
            found_errors.extend(matches)
        
        return found_errors
    
    def detect_authentication_bypass(self, results: List[AttackResult]) -> List[AttackResult]:
        """Detect potential authentication bypasses."""
        bypass_indicators = []
        
        # Group responses by status code and length
        status_groups = defaultdict(list)
        for result in results:
            status_groups[result.status_code].append(result)
        
        # Look for responses that differ significantly from the majority
        if len(status_groups) > 1:
            # Find minority status codes that might indicate bypass
            status_counts = {code: len(responses) for code, responses in status_groups.items()}
            majority_status = max(status_counts, key=status_counts.get)
            
            for status_code, responses in status_groups.items():
                if status_code != majority_status and len(responses) < len(results) * 0.1:
                    # These are potential bypasses
                    bypass_indicators.extend(responses)
        
        return bypass_indicators
    
    def detect_user_enumeration(self, results: List[AttackResult]) -> Dict[str, List[AttackResult]]:
        """Detect user enumeration vulnerabilities through timing and response analysis."""
        enumeration_results = {
            "timing_based": [],
            "response_based": [],
            "error_based": []
        }
        
        # Timing-based analysis
        response_times = [r.response_time for r in results]
        if len(response_times) > 1:
            mean_time = statistics.mean(response_times)
            stdev_time = statistics.stdev(response_times) if len(response_times) > 1 else 0
            
            for result in results:
                # Look for responses significantly slower than average
                if result.response_time > mean_time + (2 * stdev_time):
                    enumeration_results["timing_based"].append(result)
        
        # Response content analysis
        response_hashes = [self.calculate_response_hash(r.response_body) for r in results]
        hash_counts = Counter(response_hashes)
        minority_hashes = [h for h, count in hash_counts.items() if count <= len(results) * 0.1]
        
        for result in results:
            result_hash = self.calculate_response_hash(result.response_body)
            if result_hash in minority_hashes:
                enumeration_results["response_based"].append(result)
        
        # Error-based analysis
        for result in results:
            errors = self.detect_error_messages(result.response_body)
            if errors:
                enumeration_results["error_based"].append(result)
        
        return enumeration_results
    
    def smart_response_analysis(self, results: List[AttackResult]) -> Dict[str, Any]:
        """Comprehensive smart analysis of all responses."""
        analysis = {
            "total_requests": len(results),
            "unique_status_codes": len(set(r.status_code for r in results)),
            "unique_response_lengths": len(set(r.response_length for r in results)),
            "unique_response_hashes": len(set(self.calculate_response_hash(r.response_body) for r in results)),
            "potential_vulnerabilities": [],
            "interesting_responses": [],
            "error_responses": [],
            "timing_anomalies": []
        }
        
        # Detect authentication bypasses
        bypasses = self.detect_authentication_bypass(results)
        if bypasses:
            analysis["potential_vulnerabilities"].append({
                "type": "Authentication Bypass",
                "count": len(bypasses),
                "payloads": [r.payload for r in bypasses[:5]]  # First 5
            })
        
        # Detect user enumeration
        enum_results = self.detect_user_enumeration(results)
        for vuln_type, vuln_results in enum_results.items():
            if vuln_results:
                analysis["potential_vulnerabilities"].append({
                    "type": f"User Enumeration ({vuln_type.replace('_', ' ').title()})",
                    "count": len(vuln_results),
                    "payloads": [r.payload for r in vuln_results[:5]]
                })
        
        # Response clustering for anomaly detection
        response_groups = defaultdict(list)
        for result in results:
            key = (result.status_code, result.response_length, self.calculate_response_hash(result.response_body))
            response_groups[key].append(result)
        
        # Find minority response patterns
        total_responses = len(results)
        for key, group_results in response_groups.items():
            if len(group_results) <= total_responses * 0.05 and len(group_results) > 0:  # Less than 5% of responses
                analysis["interesting_responses"].extend(group_results)
        
        return analysis

class AttackEngine:
    """Enhanced attack engine with intelligent request handling."""
    
    def __init__(self, threads: int = 10, delay: float = 0, timeout: int = 10):
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.session = None
        
    async def create_session(self):
        """Create aiohttp session with proper configuration."""
        connector = aiohttp.TCPConnector(
            limit=self.threads,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=False,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'PyIntruder-Pro/2.0.0 (Advanced Security Testing)'}
        )
    
    async def close_session(self):
        """Close the aiohttp session."""
        if self.session:
            await self.session.close()
    
    async def execute_request(self, request: RequestTemplate, payload: str = "", injection_point: Tuple[str, str, str] = None) -> AttackResult:
        """Execute a single HTTP request with advanced monitoring."""
        start_time = time.time()
        
        try:
            # Smart payload injection
            if injection_point:
                injected_request = PayloadManager.inject_payload_smart(request, injection_point, payload)
            else:
                injected_request = request
            
            # Build URL
            url = f"{injected_request.scheme}://{injected_request.host}{injected_request.path}"
            
            # Prepare headers
            headers = dict(injected_request.headers)
            if 'Host' in headers:
                del headers['Host']  # aiohttp handles this automatically
            
            # Execute request with detailed tracking
            async with self.session.request(
                method=injected_request.method,
                url=url,
                headers=headers,
                data=injected_request.body if injected_request.body else None,
                allow_redirects=False  # Track redirects manually
            ) as response:
                response_body = await response.text()
                response_time = time.time() - start_time
                
                # Extract detailed response information
                analyzer = AdvancedAnalyzer()
                response_hash = analyzer.calculate_response_hash(response_body)
                
                return AttackResult(
                    payload=payload,
                    status_code=response.status,
                    response_length=len(response_body),
                    response_time=response_time,
                    response_body=response_body,
                    response_hash=response_hash,
                    headers=dict(response.headers),
                    redirect_location=response.headers.get('Location', ''),
                    content_type=response.headers.get('Content-Type', ''),
                    server_header=response.headers.get('Server', ''),
                    cookies={cookie.key: cookie.value for cookie in response.cookies.values()}
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            return AttackResult(
                payload=payload,
                status_code=0,
                response_length=0,
                response_time=response_time,
                error=str(e)
            )
        
        finally:
            if self.delay > 0:
                await asyncio.sleep(self.delay)

class PyIntruderPro:
    """Advanced PyIntruder with intelligent analysis."""
    
    def __init__(self):
        self.attack_engine = None
        self.results = []
        self.analyzer = AdvancedAnalyzer()
    
    async def run_attack(self, request_file: str, wordlist_file: str, 
                        threads: int = 10, delay: float = 0, timeout: int = 10,
                        output_file: str = None, show_all: bool = False,
                        auto_detect: bool = False, target_param: str = None,
                        manual_params: str = None):
        """Execute advanced attack with intelligent analysis."""
        
        ColorLogger.banner()
        ColorLogger.info(f"Loading request template from {request_file}")
        
        # Parse request template
        request_template = RequestParser.parse_burp_request(request_file)
        ColorLogger.success(f"Parsed {request_template.method} request to {request_template.host}")
        
        # Load payloads
        ColorLogger.info(f"Loading payloads from {wordlist_file}")
        payloads = PayloadManager.load_wordlist(wordlist_file)
        
        if not payloads:
            ColorLogger.error("No payloads loaded")
            return
            
        ColorLogger.success(f"Loaded {len(payloads)} payloads")
        
        # Determine injection strategy with priority order
        positions = PayloadManager.find_payload_positions(request_template.path + request_template.body)
        injection_points = []
        
        if manual_params:
            # Priority 1: Manual parameter specification
            ColorLogger.info("Using manually specified parameters...")
            injection_points = PayloadManager.parse_manual_parameters(manual_params)
            ColorLogger.success(f"Configured {len(injection_points)} manual injection points:")
            for context, param, value in injection_points:
                fuzz_indicator = "🎯 FUZZ" if value.upper() in ['FUZZ', 'WORDLIST'] else f"📌 {value}"
                ColorLogger.info(f"  {context.upper()}: {param} = {fuzz_indicator}")
        
        elif positions:
            # Priority 2: Marked positions with § symbols
            ColorLogger.success(f"Found {len(positions)} marked payload positions (§ symbols)")
            injection_points = [("marker", pos.param_name, "") for pos in positions]
            for pos in positions:
                ColorLogger.info(f"  MARKER: {pos.param_name} in {pos.position_type}")
        
        elif auto_detect or target_param:
            # Priority 3: Auto-detection
            ColorLogger.info("Auto-detecting injection points from request...")
            auto_points = PayloadManager.auto_detect_injection_points(request_template)
            
            if target_param:
                # Filter to specific parameter
                injection_points = [(context, param, value) for context, param, value in auto_points if param == target_param]
                if not injection_points:
                    ColorLogger.error(f"Target parameter '{target_param}' not found in request")
                    ColorLogger.info(f"Available parameters: {[param for _, param, _ in auto_points]}")
                    return
                ColorLogger.success(f"Targeting parameter: {target_param}")
            else:
                injection_points = auto_points
            
            ColorLogger.success(f"Auto-detected {len(injection_points)} injection points:")
            for context, param, value in injection_points:
                ColorLogger.info(f"  {context.upper()}: {param} = '{value}'")
        
        if not injection_points:
            ColorLogger.warning("No injection points found!")
            ColorLogger.info("[+] Try one of these approaches:")
            ColorLogger.info("   1. Use --parameters 'username:FUZZ,password:admin123'")
            ColorLogger.info("   2. Add § markers in request file: username=§admin§")
            ColorLogger.info("   3. Use --auto-detect to find parameters automatically")
            ColorLogger.info("   4. Use --target-param to specify existing parameter")
            return
        
        # Initialize attack engine
        self.attack_engine = AttackEngine(threads, delay, timeout)
        await self.attack_engine.create_session()
        
        ColorLogger.info(f"Starting advanced attack with {threads} threads")
        
        # Execute attacks for each injection point
        all_results = []
        
        for i, injection_point in enumerate(injection_points):
            context, param_name, original_value = injection_point
            
            # Determine if this parameter should use wordlist
            use_wordlist = original_value.upper() in ['FUZZ', 'WORDLIST', ''] or context == 'marker'
            
            if use_wordlist:
                ColorLogger.info(f"Fuzzing {context}.{param_name} with {len(payloads)} payloads...")
                test_payloads = payloads
            else:
                ColorLogger.info(f"Testing {context}.{param_name} with fixed value: '{original_value}'")
                test_payloads = [original_value]
            
            tasks = []
            for payload in test_payloads:
                task = self.attack_engine.execute_request(request_template, payload, injection_point)
                tasks.append(task)
            
            # Process results with progress tracking
            completed = 0
            point_results = []
            
            for coro in asyncio.as_completed(tasks):
                result = await coro
                point_results.append(result)
                completed += 1
                
                if completed % 20 == 0 or completed == len(test_payloads):
                    progress = (completed / len(test_payloads)) * 100
                    print(f"\r{Fore.CYAN}Progress [{i+1}/{len(injection_points)}]: {progress:.1f}% ({completed}/{len(test_payloads)}){Style.RESET_ALL}", end='')
            
            print(f" ✓ {context}.{param_name}")
            all_results.extend(point_results)
        
        await self.attack_engine.close_session()
        self.results = all_results
        
        # Advanced Analysis
        ColorLogger.info("Performing advanced security analysis...")
        analysis = self.analyzer.smart_response_analysis(self.results)
        
        self.display_analysis_results(analysis)
        
        # Generate detailed report
        if output_file:
            ColorLogger.info("Generating comprehensive report...")
            self.generate_advanced_report(analysis, output_file)
    
    def display_analysis_results(self, analysis: Dict[str, Any]):
        """Display advanced analysis results."""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"ADVANCED SECURITY ANALYSIS RESULTS")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        print(f"Total Requests: {analysis['total_requests']}")
        print(f"Unique Status Codes: {analysis['unique_status_codes']}")
        print(f"Unique Response Lengths: {analysis['unique_response_lengths']}")
        print(f"Unique Response Patterns: {analysis['unique_response_hashes']}")
        
        # Potential Vulnerabilities
        if analysis['potential_vulnerabilities']:
            print(f"\n{Fore.RED}[!!] POTENTIAL VULNERABILITIES DETECTED:{Style.RESET_ALL}")
            for vuln in analysis['potential_vulnerabilities']:
                ColorLogger.vuln(f"{vuln['type']}: {vuln['count']} instances")
                print(f"   Sample payloads: {', '.join(vuln['payloads'][:3])}")
        
        # Interesting Responses
        if analysis['interesting_responses']:
            print(f"\n{Fore.YELLOW}🔍 INTERESTING RESPONSES ({len(analysis['interesting_responses'])}):{Style.RESET_ALL}")
            
            # Group by response characteristics
            response_groups = defaultdict(list)
            for result in analysis['interesting_responses']:
                key = f"{result.status_code}:{result.response_length}"
                response_groups[key].append(result)
            
            for key, group in list(response_groups.items())[:10]:  # Show top 10 groups
                status, length = key.split(':')
                sample_payload = group[0].payload[:30] + "..." if len(group[0].payload) > 30 else group[0].payload
                print(f"   Status {status}, Length {length}: {len(group)} responses (e.g., '{sample_payload}')")
        
        # Error Analysis
        error_responses = [r for r in self.results if r.error]
        if error_responses:
            print(f"\n{Fore.RED}[!] ERROR RESPONSES ({len(error_responses)}):{Style.RESET_ALL}")
            error_types = Counter([r.error.split(':')[0] for r in error_responses])
            for error_type, count in error_types.most_common(5):
                print(f"   {error_type}: {count} occurrences")
    
    def generate_advanced_report(self, analysis: Dict[str, Any], output_file: str):
        """Generate comprehensive security report."""
        report = {
            "scan_info": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "tool": "PyIntruder Pro v2.0.0",
                "total_requests": len(self.results)
            },
            "analysis_summary": analysis,
            "detailed_results": []
        }
        
        # Add detailed results for interesting responses
        for result in analysis.get('interesting_responses', [])[:50]:  # Limit to 50
            report["detailed_results"].append({
                "payload": result.payload,
                "status_code": result.status_code,
                "response_length": result.response_length,
                "response_time": round(result.response_time, 3),
                "response_hash": result.response_hash,
                "error": result.error,
                "redirect_location": result.redirect_location,
                "content_type": result.content_type
            })
        
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            ColorLogger.success(f"Advanced report saved to {output_file}")
        except Exception as e:
            ColorLogger.error(f"Failed to save report: {e}")

def main():
    """Main entry point with enhanced options."""
    parser = argparse.ArgumentParser(
        description="PyIntruder Pro - Advanced Web Security Testing & Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Advanced Examples:
  # Manual parameter specification (RECOMMENDED)
  python pyintruder.py -r request.txt -w usernames.txt --parameters "username:FUZZ,password:admin123"
  python pyintruder.py -r request.txt -w payloads.txt --parameters "url:id:FUZZ,header:X-Forwarded-For:FUZZ"
  
  # Using § markers in request file
  python pyintruder.py -r request.txt -w passwords.txt  # request contains: username=§admin§
  
  # Auto-detect injection points
  python pyintruder.py -r request.txt -w usernames.txt --auto-detect
  
  # Target specific existing parameter
  python pyintruder.py -r request.txt -w passwords.txt --target-param username
  
  # Advanced multi-parameter testing
  python pyintruder.py -r request.txt -w wordlist.txt --parameters "body:user:FUZZ,header:Authorization:Bearer FUZZ"
        """
    )
    
    parser.add_argument('-r', '--request', required=True,
                       help='Request file (saved from Burp Suite)')
    parser.add_argument('-w', '--wordlist', required=True,
                       help='Wordlist file containing payloads')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of concurrent threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0,
                       help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', 
                       help='Output file for advanced report (JSON format)')
    parser.add_argument('--show-all', action='store_true',
                       help='Show all results, not just interesting ones')
    parser.add_argument('--parameters', '--params', 
                       help='Manual parameter specification: "param1:FUZZ,param2:value" or "context:param:FUZZ"')
    parser.add_argument('--auto-detect', action='store_true',
                       help='Auto-detect injection points in request')
    parser.add_argument('--target-param', 
                       help='Target specific existing parameter for injection')
    
    args = parser.parse_args()
    
    # Validate input files
    if not Path(args.request).exists():
        ColorLogger.error(f"Request file not found: {args.request}")
        sys.exit(1)
    
    if not Path(args.wordlist).exists():
        ColorLogger.error(f"Wordlist file not found: {args.wordlist}")
        sys.exit(1)
    
    # Run the advanced attack
    intruder = PyIntruderPro()
    try:
        asyncio.run(intruder.run_attack(
            request_file=args.request,
            wordlist_file=args.wordlist,
            threads=args.threads,
            delay=args.delay,
            timeout=args.timeout,
            output_file=args.output,
            show_all=args.show_all,
            auto_detect=args.auto_detect,
            target_param=args.target_param,
            manual_params=args.parameters
        ))
    except KeyboardInterrupt:
        ColorLogger.warning("Attack interrupted by user")
    except Exception as e:
        ColorLogger.critical(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
