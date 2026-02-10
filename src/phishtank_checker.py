"""
PhishTank URL Checker - No API Key Required
Checks URLs against PhishTank database in real-time
Uses public API endpoint with rate limiting awareness
"""

import requests
import base64
import time
import json
import os
from typing import Dict, Optional
from urllib.parse import quote
import logging
import hashlib
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PhishTankChecker:
    """
    Check URLs against PhishTank database
    Works WITHOUT an API key (uses public endpoint with rate limiting)

    PhishTank API Info:
    - POST to http://checkurl.phishtank.com/checkurl/
    - url: base64 or urlencoded
    - format: json or xml
    - app_key: optional (improves rate limits)

    Rate Limits (without API key):
    - Approximately 5-10 requests per minute
    - Use caching to reduce requests
    """

    def __init__(self, api_key: str = None, cache_dir: str = 'data/cache'):
        """
        Initialize PhishTank checker

        Args:
            api_key: Optional API key (get free at phishtank.com/api_register.php)
            cache_dir: Directory to store cached results
        """
        self.api_key = api_key
        self.api_endpoint = "https://checkurl.phishtank.com/checkurl/"
        self.cache_dir = cache_dir
        self.cache_file = os.path.join(cache_dir, 'phishtank_cache.json')

        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 6.0  # seconds between requests (10 req/min)
        self.request_count = 0
        self.rate_limit_window_start = time.time()

        # Cache settings
        self.cache_ttl = 24 * 60 * 60  # 24 hours
        self.cache = self._load_cache()

        # User agent (required by PhishTank)
        self.user_agent = "PhishingDetector/3.0 (Python; Educational Security Tool)"

        # Create cache directory
        os.makedirs(cache_dir, exist_ok=True)

    def _load_cache(self) -> Dict:
        """Load cached results from disk"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    cache = json.load(f)
                # Clean expired entries
                now = time.time()
                cache = {k: v for k, v in cache.items()
                        if now - v.get('timestamp', 0) < self.cache_ttl}
                return cache
        except Exception as e:
            logger.warning(f"Error loading cache: {e}")
        return {}

    def _save_cache(self):
        """Save cache to disk"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.warning(f"Error saving cache: {e}")

    def _get_cache_key(self, url: str) -> str:
        """Generate cache key for URL"""
        return hashlib.md5(url.lower().encode()).hexdigest()

    def _check_rate_limit(self) -> bool:
        """Check if we should wait before making a request"""
        now = time.time()

        # Reset counter every minute
        if now - self.rate_limit_window_start > 60:
            self.request_count = 0
            self.rate_limit_window_start = now

        # Check if we've hit rate limit
        max_requests = 20 if self.api_key else 10
        if self.request_count >= max_requests:
            wait_time = 60 - (now - self.rate_limit_window_start)
            if wait_time > 0:
                logger.warning(f"Rate limit reached. Waiting {wait_time:.1f}s")
                time.sleep(wait_time)
                self.request_count = 0
                self.rate_limit_window_start = time.time()

        # Ensure minimum interval between requests
        time_since_last = now - self.last_request_time
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)

        return True

    def check_url(self, url: str, use_cache: bool = True) -> Dict:
        """
        Check a URL against PhishTank database

        Args:
            url: URL to check
            use_cache: Whether to use cached results

        Returns:
            Dict with check result:
            - url: The checked URL
            - in_database: Whether URL is in PhishTank
            - is_phishing: True if confirmed phishing
            - phish_id: PhishTank ID (if found)
            - phish_detail_page: Link to PhishTank details
            - verified: Whether phish is verified
            - valid: Whether the entry is currently valid
            - source: 'phishtank'
            - cached: Whether result is from cache
            - error: Error message if any
        """
        result = {
            'url': url,
            'in_database': False,
            'is_phishing': False,
            'phish_id': None,
            'phish_detail_page': None,
            'verified': False,
            'valid': False,
            'source': 'phishtank',
            'cached': False,
            'timestamp': datetime.now().isoformat(),
            'error': None,
        }

        # Check cache first
        cache_key = self._get_cache_key(url)
        if use_cache and cache_key in self.cache:
            cached_result = self.cache[cache_key]
            cached_result['cached'] = True
            logger.info(f"PhishTank cache hit for: {url[:50]}...")
            return cached_result

        # Rate limiting
        self._check_rate_limit()

        try:
            # Encode URL (base64 is more reliable)
            url_encoded = base64.b64encode(url.encode()).decode()

            # Prepare POST data
            data = {
                'url': url_encoded,
                'format': 'json',
            }

            # Add API key if available
            if self.api_key:
                data['app_key'] = self.api_key

            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Origin': 'https://www.phishtank.com',
                'Referer': 'https://www.phishtank.com/',
            }

            logger.info(f"Checking URL with PhishTank: {url[:50]}...")

            # Make request
            response = requests.post(
                self.api_endpoint,
                data=data,
                headers=headers,
                timeout=15
            )

            self.last_request_time = time.time()
            self.request_count += 1

            # Check for rate limiting
            if response.status_code == 509:
                result['error'] = 'Rate limit exceeded. Please wait and try again.'
                logger.warning("PhishTank rate limit exceeded")
                return result

            if response.status_code == 403:
                # Cloudflare protection - PhishTank blocks automated requests
                result['error'] = 'PhishTank blocked (Cloudflare). Get free API key at phishtank.com/api_register.php'
                logger.warning("PhishTank returned 403 - Cloudflare protection. Consider getting a free API key.")
                return result

            if response.status_code != 200:
                result['error'] = f'HTTP {response.status_code}: {response.text[:100]}'
                return result

            # Parse response
            try:
                data = response.json()
            except json.JSONDecodeError:
                result['error'] = 'Invalid JSON response from PhishTank'
                return result

            # Process results
            results = data.get('results', {})
            result['in_database'] = results.get('in_database', False)

            if result['in_database']:
                result['phish_id'] = results.get('phish_id')
                result['phish_detail_page'] = results.get('phish_detail_page')
                result['verified'] = results.get('verified', False)
                result['valid'] = results.get('valid', False)

                # URL is phishing if it's in database and verified
                if results.get('verified') or results.get('valid'):
                    result['is_phishing'] = True

            # Cache the result
            self.cache[cache_key] = result.copy()
            self.cache[cache_key]['timestamp'] = time.time()
            self._save_cache()

            logger.info(f"PhishTank result: in_database={result['in_database']}, phishing={result['is_phishing']}")

        except requests.exceptions.Timeout:
            result['error'] = 'Request timeout - PhishTank may be slow'
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection error - check internet connection'
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"PhishTank check error: {e}")

        return result

    def check_urls_batch(self, urls: list, delay: float = 6.0) -> list:
        """
        Check multiple URLs with rate limiting

        Args:
            urls: List of URLs to check
            delay: Delay between requests (seconds)

        Returns:
            List of check results
        """
        results = []

        for i, url in enumerate(urls):
            logger.info(f"Checking URL {i+1}/{len(urls)}: {url[:50]}...")
            result = self.check_url(url)
            results.append(result)

            # Don't delay after the last URL or if result was cached
            if i < len(urls) - 1 and not result.get('cached'):
                time.sleep(delay)

        return results

    def get_stats(self) -> Dict:
        """Get checker statistics"""
        return {
            'api_key_set': bool(self.api_key),
            'cache_size': len(self.cache),
            'requests_this_minute': self.request_count,
            'rate_limit': 20 if self.api_key else 10,
        }

    def clear_cache(self):
        """Clear the URL cache"""
        self.cache = {}
        if os.path.exists(self.cache_file):
            os.remove(self.cache_file)
        logger.info("PhishTank cache cleared")


# Alternative: PhishTank website scraper (backup method)
class PhishTankWebChecker:
    """
    Alternative checker using PhishTank website
    Use this if API is not working
    Note: For educational purposes only
    """

    def __init__(self):
        self.search_url = "https://www.phishtank.com/phish_search.php"
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def search_url(self, url: str) -> Dict:
        """
        Search for URL on PhishTank website
        Returns basic info about whether URL appears in search results
        """
        result = {
            'url': url,
            'found_in_search': False,
            'source': 'phishtank_web',
            'error': None,
        }

        try:
            # This would search the website
            # Note: Web scraping should be done responsibly
            # For production use, prefer the API
            result['error'] = 'Web search not implemented - use API instead'
        except Exception as e:
            result['error'] = str(e)

        return result


# Singleton instance
_checker_instance = None

def get_phishtank_checker(api_key: str = None) -> PhishTankChecker:
    """Get singleton PhishTank checker instance"""
    global _checker_instance
    if _checker_instance is None:
        _checker_instance = PhishTankChecker(api_key=api_key)
    return _checker_instance


if __name__ == '__main__':
    print("=" * 60)
    print("PhishTank URL Checker - No API Key Required")
    print("=" * 60)

    checker = PhishTankChecker()

    print(f"\nChecker Stats: {checker.get_stats()}")
    print("\nNote: Without API key, rate limit is ~10 requests/minute")
    print("Get a free API key at: https://www.phishtank.com/api_register.php")

    # Test URLs
    test_urls = [
        # Known legitimate URLs
        'https://www.google.com',
        'https://www.paypal.com',

        # Suspicious patterns (may or may not be in PhishTank)
        'http://paypal-verify.suspicious-domain.xyz',
    ]

    print("\n" + "-" * 60)
    print("Testing URLs (with rate limiting):")
    print("-" * 60)

    for url in test_urls:
        print(f"\nChecking: {url}")
        result = checker.check_url(url)

        if result['error']:
            print(f"  Error: {result['error']}")
        else:
            print(f"  In PhishTank DB: {result['in_database']}")
            print(f"  Is Phishing: {result['is_phishing']}")
            if result['phish_id']:
                print(f"  Phish ID: {result['phish_id']}")
                print(f"  Details: {result['phish_detail_page']}")

        # Wait between requests to respect rate limits
        if not result.get('cached'):
            print("  (Waiting 6s for rate limit...)")
            time.sleep(6)

    print("\n" + "=" * 60)
    print("Done! Check https://www.phishtank.com for more info")
    print("=" * 60)
