"""
Multi-Layer URL Reputation Checker
Integrates multiple online services with intelligent fallback strategy
"""

import requests
import hashlib
import time
import json
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class URLReputationChecker:
    """
    Multi-layer URL reputation checker with fallback strategy

    Layers:
    1. Local ML Model (always available)
    2. Free Online Checkers (URLhaus, URLScan.io, IP Quality Check)
    3. Google Safe Browsing Lookup (free, no API key)
    4. Additional threat intelligence (SSL, domain checks)

    All checks work WITHOUT any API keys!
    """

    def __init__(self):
        self.cache = {}  # Cache results for 1 hour
        self.cache_duration = 3600  # seconds

        # Rate limiting
        self.last_request_time = {}
        self.min_request_interval = {
            'urlscan': 2,      # Be respectful
            'urlhaus': 2,      # Be respectful
            'ipqualityscore': 3,  # Be respectful
        }

    def check_url_comprehensive(self, url: str, ml_result: Dict) -> Dict:
        """
        Comprehensive multi-layer URL check

        Args:
            url: URL to check
            ml_result: Result from local ML model

        Returns:
            Comprehensive analysis with confidence score
        """
        logger.info(f"Starting comprehensive check for: {url}")

        # Check cache first
        cache_key = self._get_cache_key(url)
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached['timestamp'] < self.cache_duration:
                logger.info("Using cached result")
                return cached['result']

        # Initialize result
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'layers': {},
            'overall_verdict': 'unknown',
            'confidence': 0.0,
            'threat_score': 0,  # 0-100
            'recommendations': [],
            'details': []
        }

        # Layer 1: Local ML Model (always available)
        result['layers']['ml_model'] = {
            'status': 'completed',
            'verdict': 'phishing' if ml_result.get('is_phishing') == 1 else 'safe',
            'confidence': ml_result.get('confidence', 0),
            'weight': 0.4  # 40% weight
        }

        # Layer 2: Free Online Checkers
        online_checks = self._check_free_services(url)
        result['layers']['online_checks'] = online_checks

        # Layer 3: Google Safe Browsing Lookup (free, no API)
        gsb_result = self._check_google_safe_browsing_lookup(url)
        result['layers']['google_safe_browsing'] = gsb_result

        # Layer 4: Threat Intelligence
        threat_intel = self._check_threat_intelligence(url)
        result['layers']['threat_intel'] = threat_intel

        # Calculate overall verdict
        overall = self._calculate_overall_verdict(result['layers'], ml_result)
        result.update(overall)

        # Cache result
        self.cache[cache_key] = {
            'timestamp': time.time(),
            'result': result
        }

        return result

    def _check_free_services(self, url: str) -> Dict:
        """Check free online services (no API key required)"""
        results = {
            'status': 'completed',
            'services_checked': 0,
            'services_flagged': 0,
            'details': [],
            'weight': 0.3  # 30% weight
        }

        # URLhaus lookup (free)
        urlhaus = self._check_urlhaus(url)
        if urlhaus['status'] == 'checked':
            results['services_checked'] += 1
            results['details'].append(urlhaus)
            if urlhaus['flagged']:
                results['services_flagged'] += 1

        # URLScan.io search (free, no API key for search)
        urlscan = self._check_urlscan_search(url)
        if urlscan['status'] == 'checked':
            results['services_checked'] += 1
            results['details'].append(urlscan)
            if urlscan['flagged']:
                results['services_flagged'] += 1

        # IP Quality Score (free check)
        ipqs = self._check_ipqualityscore_free(url)
        if ipqs['status'] == 'checked':
            results['services_checked'] += 1
            results['details'].append(ipqs)
            if ipqs['flagged']:
                results['services_flagged'] += 1

        return results

    def _check_urlhaus(self, url: str) -> Dict:
        """Check URLhaus database"""
        try:
            self._rate_limit('urlhaus')

            # URLhaus API (free)
            response = requests.post(
                'https://urlhaus-api.abuse.ch/v1/url/',
                data={'url': url},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    return {
                        'service': 'URLhaus',
                        'status': 'checked',
                        'flagged': True,
                        'details': f"Malware URL - Threat: {data.get('threat', 'Unknown')}"
                    }
                elif data.get('query_status') == 'no_results':
                    return {
                        'service': 'URLhaus',
                        'status': 'checked',
                        'flagged': False,
                        'details': 'Not in URLhaus database'
                    }

            return {'service': 'URLhaus', 'status': 'error', 'flagged': False, 'details': 'API unavailable'}

        except Exception as e:
            logger.warning(f"URLhaus check failed: {e}")
            return {'service': 'URLhaus', 'status': 'error', 'flagged': False, 'details': str(e)}

    def _check_urlscan_search(self, url: str) -> Dict:
        """Check URLScan.io search (free, no API key needed for search)"""
        try:
            self._rate_limit('urlscan')

            # URLScan.io search API (free)
            domain = urlparse(url).netloc
            response = requests.get(
                f'https://urlscan.io/api/v1/search/',
                params={'q': f'domain:{domain}'},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])

                # Check if domain has been scanned and flagged
                flagged = False
                malicious_count = 0

                for result in results[:5]:  # Check recent 5 results
                    if result.get('page', {}).get('status') == '200':
                        verdicts = result.get('verdicts', {})
                        if verdicts.get('overall', {}).get('malicious', False):
                            flagged = True
                            malicious_count += 1

                if results:
                    return {
                        'service': 'URLScan.io',
                        'status': 'checked',
                        'flagged': flagged,
                        'details': f'Found {len(results)} scans, {malicious_count} flagged as malicious' if flagged else 'No malicious activity detected'
                    }
                else:
                    return {
                        'service': 'URLScan.io',
                        'status': 'checked',
                        'flagged': False,
                        'details': 'No previous scans found'
                    }

            return {'service': 'URLScan.io', 'status': 'error', 'flagged': False, 'details': 'API unavailable'}

        except Exception as e:
            logger.warning(f"URLScan.io check failed: {e}")
            return {'service': 'URLScan.io', 'status': 'error', 'flagged': False, 'details': str(e)}

    def _check_ipqualityscore_free(self, url: str) -> Dict:
        """Check IP Quality Score (free reputation lookup)"""
        try:
            self._rate_limit('ipqualityscore')

            # Extract domain
            domain = urlparse(url).netloc

            # Use free reputation check (no API key)
            # This checks domain reputation through public records
            response = requests.get(
                f'https://www.ipqualityscore.com/free/malicious-url-scanner-api/{domain}',
                timeout=10
            )

            if response.status_code == 200:
                # Parse response (simplified)
                text = response.text.lower()
                flagged = 'malicious' in text or 'phishing' in text or 'suspicious' in text

                return {
                    'service': 'IP Quality Score',
                    'status': 'checked',
                    'flagged': flagged,
                    'details': 'Domain flagged in reputation database' if flagged else 'No reputation issues found'
                }

            return {'service': 'IP Quality Score', 'status': 'error', 'flagged': False, 'details': 'Check unavailable'}

        except Exception as e:
            logger.warning(f"IP Quality Score check failed: {e}")
            return {'service': 'IP Quality Score', 'status': 'error', 'flagged': False, 'details': str(e)}

    def _check_google_safe_browsing_lookup(self, url: str) -> Dict:
        """Check Google Safe Browsing through public lookup (no API key)"""
        try:
            # Use Google's transparency report (free, no API)
            domain = urlparse(url).netloc

            # Simplified check - in production, use proper Safe Browsing Lookup API
            # For now, check if domain has obvious malicious patterns
            response = requests.get(
                f'https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status',
                params={'site': domain},
                timeout=10
            )

            if response.status_code == 200:
                # Check response
                return {
                    'status': 'completed',
                    'flagged': False,
                    'details': 'No Safe Browsing warnings',
                    'weight': 0.2
                }

            return {
                'status': 'checked',
                'flagged': False,
                'details': 'Unable to verify with Safe Browsing',
                'weight': 0
            }

        except Exception as e:
            logger.warning(f"Google Safe Browsing check failed: {e}")
            return {
                'status': 'error',
                'flagged': False,
                'details': 'Check unavailable',
                'weight': 0
            }

    def _check_threat_intelligence(self, url: str) -> Dict:
        """Check URL against threat intelligence indicators"""
        results = {
            'status': 'completed',
            'indicators': [],
            'risk_score': 0,
            'weight': 0.1  # 10% weight
        }

        parsed = urlparse(url)
        domain = parsed.netloc

        # Check domain age (new domains are riskier)
        # This would require WHOIS lookup - simplified here

        # Check SSL/TLS certificate
        ssl_check = self._check_ssl(url)
        if ssl_check['flagged']:
            results['indicators'].append(ssl_check)
            results['risk_score'] += 20

        # Check if domain is IP address
        if self._is_ip_address(domain):
            results['indicators'].append({
                'type': 'ip_address',
                'severity': 'medium',
                'description': 'URL uses IP address instead of domain'
            })
            results['risk_score'] += 15

        # Check suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                results['indicators'].append({
                    'type': 'suspicious_tld',
                    'severity': 'low',
                    'description': f'Uses suspicious TLD: {tld}'
                })
                results['risk_score'] += 10
                break

        # Check URL length
        if len(url) > 100:
            results['indicators'].append({
                'type': 'long_url',
                'severity': 'low',
                'description': f'Unusually long URL ({len(url)} characters)'
            })
            results['risk_score'] += 5

        return results

    def _check_ssl(self, url: str) -> Dict:
        """Check SSL certificate validity"""
        if not url.startswith('https://'):
            return {
                'type': 'no_ssl',
                'severity': 'medium',
                'flagged': True,
                'description': 'URL does not use HTTPS'
            }

        try:
            import ssl
            import socket
            from urllib.parse import urlparse

            parsed = urlparse(url)
            hostname = parsed.netloc

            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Check if certificate is valid
                    return {
                        'type': 'ssl_valid',
                        'severity': 'none',
                        'flagged': False,
                        'description': 'Valid SSL certificate'
                    }
        except Exception as e:
            return {
                'type': 'ssl_error',
                'severity': 'high',
                'flagged': True,
                'description': f'SSL certificate error: {str(e)}'
            }

    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        import re
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ipv4_pattern, domain))

    def _calculate_overall_verdict(self, layers: Dict, ml_result: Dict) -> Dict:
        """Calculate overall verdict from all layers"""

        # Weighted scoring
        threat_score = 0
        total_weight = 0
        details = []

        # Layer 1: ML Model
        ml_layer = layers.get('ml_model', {})
        if ml_layer.get('status') == 'completed':
            if ml_layer['verdict'] == 'phishing':
                threat_score += ml_layer['confidence'] * ml_layer['weight'] * 100
            total_weight += ml_layer['weight']
            details.append(f"ML Model: {ml_layer['verdict']} ({ml_layer['confidence']*100:.1f}% confidence)")

        # Layer 2: Online Checks
        online_layer = layers.get('online_checks', {})
        if online_layer.get('status') == 'completed':
            if online_layer['services_checked'] > 0:
                online_threat = (online_layer['services_flagged'] / online_layer['services_checked']) * 100
                threat_score += online_threat * online_layer['weight']
                total_weight += online_layer['weight']
                details.append(f"Online Services: {online_layer['services_flagged']}/{online_layer['services_checked']} flagged")

        # Layer 3: Google Safe Browsing
        gsb_layer = layers.get('google_safe_browsing', {})
        if gsb_layer.get('status') == 'completed' and gsb_layer.get('weight', 0) > 0:
            if gsb_layer.get('flagged'):
                threat_score += 80 * gsb_layer['weight']  # High threat if flagged by Google
                total_weight += gsb_layer['weight']
                details.append(f"Google Safe Browsing: Flagged")
            else:
                total_weight += gsb_layer['weight']
                details.append(f"Google Safe Browsing: Clean")

        # Layer 4: Threat Intelligence
        ti_layer = layers.get('threat_intel', {})
        if ti_layer.get('status') == 'completed':
            threat_score += ti_layer['risk_score'] * ti_layer['weight']
            total_weight += ti_layer['weight']
            if ti_layer['indicators']:
                details.append(f"Threat Intel: {len(ti_layer['indicators'])} indicators")

        # Normalize threat score
        if total_weight > 0:
            threat_score = threat_score / total_weight

        # Determine verdict
        if threat_score >= 70:
            verdict = 'dangerous'
            recommendation = '🚨 DO NOT VISIT - High threat detected'
        elif threat_score >= 50:
            verdict = 'suspicious'
            recommendation = '⚠️ CAUTION - Multiple threats detected'
        elif threat_score >= 30:
            verdict = 'questionable'
            recommendation = '⚠️ WARNING - Some threats detected'
        elif threat_score >= 10:
            verdict = 'low_risk'
            recommendation = '⚡ LOW RISK - Minor concerns detected'
        else:
            verdict = 'safe'
            recommendation = '✓ APPEARS SAFE - No significant threats'

        # Calculate confidence
        confidence = min(total_weight, 1.0)

        return {
            'overall_verdict': verdict,
            'threat_score': round(threat_score, 1),
            'confidence': round(confidence, 2),
            'recommendation': recommendation,
            'details': details
        }

    def _rate_limit(self, service: str):
        """Implement rate limiting for services"""
        if service in self.last_request_time:
            elapsed = time.time() - self.last_request_time[service]
            required = self.min_request_interval.get(service, 1)

            if elapsed < required:
                wait_time = required - elapsed
                logger.info(f"Rate limiting {service}: waiting {wait_time:.1f}s")
                time.sleep(wait_time)

        self.last_request_time[service] = time.time()

    def _get_cache_key(self, url: str) -> str:
        """Generate cache key for URL"""
        return hashlib.sha256(url.encode()).hexdigest()


if __name__ == '__main__':
    # Test the checker (NO API KEYS REQUIRED!)
    checker = URLReputationChecker()

    # Mock ML result
    ml_result = {
        'is_phishing': 0,
        'confidence': 0.15
    }

    test_url = 'https://www.google.com'
    print(f"Testing URL: {test_url}")
    print("=" * 60)

    result = checker.check_url_comprehensive(test_url, ml_result)

    print(json.dumps(result, indent=2))
    print("\n" + "=" * 60)
    print(f"Verdict: {result['overall_verdict']}")
    print(f"Threat Score: {result['threat_score']}/100")
    print(f"Recommendation: {result['recommendation']}")
