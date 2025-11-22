# api/html_analyzer.py
# HTML Content Analyzer for Phish-Guard
# Performs deep content analysis to detect phishing indicators

"""
═══════════════════════════════════════════════════════════════════════════════
HTML CONTENT ANALYSIS SYSTEM
═══════════════════════════════════════════════════════════════════════════════

This module performs Level 3 analysis by examining actual page content.
It's only called when AI models flag a URL as suspicious.

DETECTION INDICATORS:
1. Password Input Fields (50 points) - Strong phishing indicator
2. External Form Actions (30 points) - Forms sending data to other domains
3. Sensitive Keywords (20 points) - Credit card, SSN, CVV requests
4. Connection Issues (10 points) - Timeout, unreachable pages

SCORING:
- Score >= 20: Suspicious (confirms phishing)
- Score < 20: Clean (overrides model prediction)

This helps reduce false positives while catching real threats.
═══════════════════════════════════════════════════════════════════════════════
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import logging

# Configure logging
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

# Timeout for HTTP requests (seconds)
REQUEST_TIMEOUT = 4

# User agent to identify our scanner
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard-Scanner/1.0'

# Sensitive keywords that indicate credential/payment requests
SENSITIVE_KEYWORDS = [
    'credit card',
    'card number',
    'cvv',
    'cvc',
    'ssn',
    'social security',
    'payment info',
    'banking',
    'account number',
    'routing number',
    'debit card',
    'pin code',
    'security code'
]

# Suspicion threshold (points)
SUSPICION_THRESHOLD = 20

# ═══════════════════════════════════════════════════════════════════════════
# MAIN ANALYSIS FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

def inspect_page_content(url):
    """
    Analyze HTML content of a URL to detect phishing indicators.
    
    This function performs deep content analysis including:
    - Password field detection
    - External form action detection
    - Sensitive keyword detection
    
    Args:
        url (str): URL to analyze
        
    Returns:
        dict: Analysis results containing:
            - suspicious (bool): True if page is suspicious
            - evidence (list): List of evidence found
            - score (int): Suspicion score (0-100)
            - error (str, optional): Error message if analysis failed
    """
    evidence = []
    score = 0
    
    print(f"  🌐 Fetching page content...")
    
    try:
        # ───────────────────────────────────────────────────────────────────
        # Step 1: Attempt to fetch the page
        # ───────────────────────────────────────────────────────────────────
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={'User-Agent': USER_AGENT},
            allow_redirects=True
        )
        
        # Check HTTP status code
        if response.status_code != 200:
            logger.warning(f"Page returned status {response.status_code}")
            return {
                "suspicious": True,
                "evidence": [f"Page returned HTTP {response.status_code} status"],
                "score": 10,
                "error": f"Non-200 status code: {response.status_code}"
            }
        
        print(f"  ✓ Page fetched successfully (Status: {response.status_code})")
        
        # ───────────────────────────────────────────────────────────────────
        # Step 2: Parse HTML content
        # ───────────────────────────────────────────────────────────────────
        soup = BeautifulSoup(response.text, 'html.parser')
        domain = urlparse(url).netloc
        
        # ───────────────────────────────────────────────────────────────────
        # Check 1: Password Input Fields (50 points)
        # ───────────────────────────────────────────────────────────────────
        print(f"  🔐 Checking for password fields...")
        password_inputs = soup.find_all('input', {'type': 'password'})
        
        if password_inputs:
            count = len(password_inputs)
            evidence.append(f"Found {count} password input field(s)")
            score += 50
            logger.info(f"Found {count} password field(s) on {url}")
            print(f"    ⚠️  Found {count} password field(s) [+50 points]")
        else:
            print(f"    ✓ No password fields detected")
        
        # ───────────────────────────────────────────────────────────────────
        # Check 2: Forms with External Actions (30 points)
        # ───────────────────────────────────────────────────────────────────
        print(f"  📝 Checking form actions...")
        forms = soup.find_all('form')
        external_forms = []
        
        for form in forms:
            action = form.get('action', '').strip()
            
            # Skip empty or relative URLs
            if not action or not action.startswith('http'):
                continue
            
            try:
                action_domain = urlparse(action).netloc
                
                # Check if form sends data to external domain
                if action_domain and domain not in action_domain:
                    external_forms.append(action_domain)
            except Exception as e:
                logger.debug(f"Error parsing form action: {e}")
        
        if external_forms:
            unique_domains = list(set(external_forms))
            domains_str = ", ".join(unique_domains)
            evidence.append(f"Form(s) send data to external domain(s): {domains_str}")
            score += 30
            logger.warning(f"External form actions found: {domains_str}")
            print(f"    ⚠️  Form sends data to: {domains_str} [+30 points]")
        else:
            print(f"    ✓ No external form actions detected")
        
        # ───────────────────────────────────────────────────────────────────
        # Check 3: Sensitive Keywords (20 points)
        # ───────────────────────────────────────────────────────────────────
        print(f"  🔍 Scanning for sensitive keywords...")
        page_text = soup.get_text().lower()
        found_keywords = []
        
        for keyword in SENSITIVE_KEYWORDS:
            if keyword in page_text:
                found_keywords.append(keyword)
        
        if found_keywords:
            keywords_str = ", ".join(found_keywords[:3])  # Show first 3
            if len(found_keywords) > 3:
                keywords_str += f" (and {len(found_keywords) - 3} more)"
            
            evidence.append(f"Requests sensitive info: {keywords_str}")
            score += 20
            logger.info(f"Sensitive keywords found: {found_keywords}")
            print(f"    ⚠️  Found sensitive keywords: {keywords_str} [+20 points]")
        else:
            print(f"    ✓ No sensitive keywords detected")
        
        # ───────────────────────────────────────────────────────────────────
        # Final Decision
        # ───────────────────────────────────────────────────────────────────
        is_suspicious = score >= SUSPICION_THRESHOLD
        
        print(f"  📊 Total Score: {score}/100")
        print(f"  {'🚨 SUSPICIOUS' if is_suspicious else '✅ CLEAN'}")
        
        return {
            "suspicious": is_suspicious,
            "evidence": evidence,
            "score": score
        }
    
    # ───────────────────────────────────────────────────────────────────────
    # Error Handling
    # ───────────────────────────────────────────────────────────────────────
    
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout accessing {url}")
        print(f"  ⚠️  Connection timeout")
        return {
            "suspicious": True,
            "evidence": ["Connection timeout (suspicious behavior)"],
            "score": 10,
            "error": "Request timeout"
        }
    
    except requests.exceptions.ConnectionError:
        logger.warning(f"Connection error accessing {url}")
        print(f"  ⚠️  Connection error")
        return {
            "suspicious": True,
            "evidence": ["Unable to connect to server"],
            "score": 10,
            "error": "Connection error"
        }
    
    except requests.exceptions.TooManyRedirects:
        logger.warning(f"Too many redirects for {url}")
        print(f"  ⚠️  Too many redirects")
        return {
            "suspicious": True,
            "evidence": ["Excessive redirects detected"],
            "score": 15,
            "error": "Too many redirects"
        }
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error for {url}: {e}")
        print(f"  ❌ Request error: {e}")
        return {
            "suspicious": True,
            "evidence": [f"Request failed: {str(e)[:50]}"],
            "score": 10,
            "error": str(e)
        }
    
    except Exception as e:
        logger.error(f"Unexpected error analyzing {url}: {e}")
        print(f"  ❌ Analysis error: {e}")
        return {
            "suspicious": True,
            "evidence": [f"Analysis failed: {str(e)[:50]}"],
            "score": 5,
            "error": str(e)
        }

# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def test_analyzer(url):
    """
    Test the HTML analyzer on a specific URL.
    Useful for debugging and manual testing.
    
    Args:
        url (str): URL to test
    """
    print(f"\n{'='*70}")
    print(f"Testing HTML Analyzer on: {url}")
    print(f"{'='*70}\n")
    
    result = inspect_page_content(url)
    
    print(f"\n{'─'*70}")
    print("RESULTS:")
    print(f"{'─'*70}")
    print(f"Suspicious: {result['suspicious']}")
    print(f"Score: {result['score']}/100")
    print(f"Evidence: {result['evidence']}")
    if 'error' in result:
        print(f"Error: {result['error']}")
    print(f"{'='*70}\n")
    
    return result

# ═══════════════════════════════════════════════════════════════════════════
# MAIN - For testing
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Test with sample URLs
    test_urls = [
        "https://www.google.com",
        "https://www.facebook.com/login",
    ]
    
    for test_url in test_urls:
        test_analyzer(test_url)