"""
Advanced Domain Validator - Intelligent URL Classification System
Determines if URLs are:
1. Real domains on the internet (DNS exists)
2. Fake/non-existent domains (not on internet)
3. Random garbage URLs
4. Syntactically invalid URLs

This module adds a critical layer that the original system was missing!
"""

import re
import socket
import dns.resolver
import dns.exception
import whois
from urllib.parse import urlparse
from typing import Dict, Tuple, Optional
import logging
import time
from datetime import datetime
import tldextract
import idna

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AdvancedDomainValidator:
    """
    Intelligent domain validation system that determines URL legitimacy
    Goes beyond pattern matching to check actual internet existence
    """

    def __init__(self):
        # Valid TLD list (top 100+ real TLDs)
        self.valid_tlds = {
            'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
            'co', 'uk', 'us', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'in', 'br', 'ru',
            'io', 'ai', 'app', 'dev', 'cloud', 'tech', 'online', 'site', 'store',
            'biz', 'info', 'name', 'pro', 'museum', 'aero', 'coop', 'jobs', 'travel',
            'mobi', 'tel', 'asia', 'cat', 'xxx', 'post',
            # Free/cheap TLDs (suspicious but valid)
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link',
            'icu', 'pw', 'cc', 'ws', 'buzz', 'loan'
        }

        # Initialize DNS resolver with multiple servers for reliability
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [
            '8.8.8.8',      # Google DNS
            '8.8.4.4',      # Google DNS Secondary
            '1.1.1.1',      # Cloudflare DNS
            '208.67.222.222' # OpenDNS
        ]
        self.resolver.timeout = 3
        self.resolver.lifetime = 3

    def validate_url_comprehensive(self, url: str) -> Dict:
        """
        Comprehensive URL validation that determines:
        - Is it syntactically valid?
        - Is it on the internet (DNS exists)?
        - Is it random garbage?
        - What are the specific issues?

        Returns detailed classification and recommendations
        """
        result = {
            'url': url,
            'is_valid_syntax': False,
            'is_on_internet': False,
            'is_random_garbage': False,
            'classification': 'UNKNOWN',
            'confidence': 0.0,
            'issues': [],
            'details': {},
            'recommendation': '',
            'threat_level': 0  # 0-100
        }

        # Step 1: Syntax validation
        syntax_check = self._validate_syntax(url)
        result['is_valid_syntax'] = syntax_check['is_valid']
        result['details']['syntax'] = syntax_check

        if not syntax_check['is_valid']:
            result['classification'] = 'INVALID_SYNTAX'
            result['is_random_garbage'] = syntax_check.get('is_garbage', True)
            result['issues'].extend(syntax_check.get('errors', []))
            result['recommendation'] = 'This is not a valid URL format. Cannot be accessed.'
            result['threat_level'] = 0
            return result

        # Step 2: Extract domain components
        domain_info = self._extract_domain_components(url)
        result['details']['domain_info'] = domain_info

        # Step 3: TLD validation
        tld_check = self._validate_tld(domain_info['tld'])
        result['details']['tld_check'] = tld_check

        if not tld_check['is_valid_tld']:
            result['classification'] = 'INVALID_TLD'
            result['is_random_garbage'] = True
            result['issues'].append(f"Invalid or non-existent TLD: .{domain_info['tld']}")
            result['recommendation'] = 'This domain uses an invalid or non-existent top-level domain.'
            result['threat_level'] = 5
            return result

        # Step 4: Check if domain looks like random garbage
        garbage_check = self._check_random_garbage(domain_info['domain'])
        result['details']['garbage_check'] = garbage_check
        result['is_random_garbage'] = garbage_check['is_likely_garbage']

        if garbage_check['is_likely_garbage']:
            result['issues'].extend(garbage_check['reasons'])

        # Step 5: DNS existence check (IS IT ON THE INTERNET?)
        dns_check = self._check_dns_existence(domain_info['full_domain'])
        result['details']['dns_check'] = dns_check
        result['is_on_internet'] = dns_check['exists']

        # Step 6: Additional checks if domain exists
        if dns_check['exists']:
            # WHOIS check
            whois_check = self._check_whois_info(domain_info['full_domain'])
            result['details']['whois_check'] = whois_check

            # IP reputation check
            if dns_check.get('ip_addresses'):
                ip_check = self._check_ip_reputation(dns_check['ip_addresses'])
                result['details']['ip_check'] = ip_check

        # Step 7: Final classification
        result = self._determine_final_classification(result)

        return result

    def _validate_syntax(self, url: str) -> Dict:
        """Validate URL syntax"""
        errors = []
        is_valid = True
        is_garbage = False

        if not url or not isinstance(url, str):
            return {'is_valid': False, 'errors': ['Empty or invalid URL type'], 'is_garbage': True}

        url = url.strip()

        # Check for basic URL structure
        if len(url) < 4:
            return {'is_valid': False, 'errors': ['URL too short'], 'is_garbage': True}

        # Add scheme if missing
        if not url.startswith(('http://', 'https://', 'ftp://')):
            url = 'http://' + url

        try:
            parsed = urlparse(url)

            # Must have a network location (domain)
            if not parsed.netloc:
                errors.append('Missing domain name')
                is_valid = False
                is_garbage = True

            # Check for valid characters in domain
            if parsed.netloc:
                # Remove port if present
                domain = parsed.netloc.split(':')[0]

                # Check for spaces (invalid)
                if ' ' in domain:
                    errors.append('Domain contains spaces')
                    is_valid = False
                    is_garbage = True

                # Check for invalid characters
                if re.search(r'[<>\"\'{}|\\^`\[\]]', domain):
                    errors.append('Domain contains invalid characters')
                    is_valid = False
                    is_garbage = True

                # Check for consecutive dots
                if '..' in domain:
                    errors.append('Domain contains consecutive dots')
                    is_valid = False

                # Check if it's all numbers and dots (might be IP)
                if re.match(r'^[\d.]+$', domain):
                    # Could be IP address - validate it
                    if not self._is_valid_ip(domain):
                        errors.append('Invalid IP address format')
                        is_valid = False

            # Check path for extremely suspicious patterns
            if parsed.path:
                # Check for null bytes
                if '\x00' in parsed.path:
                    errors.append('Path contains null bytes')
                    is_valid = False
                    is_garbage = True

            return {
                'is_valid': is_valid,
                'errors': errors,
                'is_garbage': is_garbage,
                'parsed_url': url,
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path': parsed.path
            }

        except Exception as e:
            return {
                'is_valid': False,
                'errors': [f'URL parsing error: {str(e)}'],
                'is_garbage': True
            }

    def _extract_domain_components(self, url: str) -> Dict:
        """Extract domain components using tldextract"""
        try:
            # Add scheme if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            extracted = tldextract.extract(url)

            return {
                'subdomain': extracted.subdomain,
                'domain': extracted.domain,
                'tld': extracted.suffix if extracted.suffix else extracted.domain.split('.')[-1] if '.' in extracted.domain else '',
                'full_domain': f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain,
                'registered_domain': extracted.registered_domain
            }
        except Exception as e:
            logger.error(f"Error extracting domain components: {e}")
            return {
                'subdomain': '',
                'domain': '',
                'tld': '',
                'full_domain': '',
                'registered_domain': ''
            }

    def _validate_tld(self, tld: str) -> Dict:
        """Validate if TLD exists in real world"""
        if not tld:
            return {
                'is_valid_tld': False,
                'tld': tld,
                'category': 'none'
            }

        tld_lower = tld.lower().replace('.', '')

        # Check against known TLD list
        is_valid = tld_lower in self.valid_tlds

        # Categorize TLD
        category = 'unknown'
        if tld_lower in {'com', 'net', 'org', 'edu', 'gov'}:
            category = 'common'
        elif tld_lower in {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top'}:
            category = 'free_suspicious'
        elif tld_lower in {'io', 'ai', 'app', 'dev', 'tech'}:
            category = 'tech'
        elif is_valid:
            category = 'valid'

        return {
            'is_valid_tld': is_valid,
            'tld': tld,
            'category': category
        }

    def _check_random_garbage(self, domain: str) -> Dict:
        """
        Detect if domain looks like random garbage
        Uses multiple heuristics
        """
        if not domain:
            return {'is_likely_garbage': True, 'confidence': 1.0, 'reasons': ['Empty domain']}

        reasons = []
        garbage_score = 0

        # 1. Check for excessive consonants (no vowels)
        vowels = set('aeiou')
        has_vowel = any(c in vowels for c in domain.lower())
        if not has_vowel and len(domain) > 4:
            garbage_score += 30
            reasons.append('No vowels in domain (likely random)')

        # 2. Check consonant-to-vowel ratio
        consonants = sum(1 for c in domain.lower() if c.isalpha() and c not in vowels)
        vowel_count = sum(1 for c in domain.lower() if c in vowels)
        if vowel_count > 0:
            ratio = consonants / vowel_count
            if ratio > 5:  # Too many consonants
                garbage_score += 20
                reasons.append(f'Excessive consonants (ratio: {ratio:.1f}:1)')

        # 3. Check for excessive numbers
        digit_ratio = sum(1 for c in domain if c.isdigit()) / len(domain) if len(domain) > 0 else 0
        if digit_ratio > 0.4:
            garbage_score += 25
            reasons.append(f'Too many digits ({digit_ratio*100:.0f}%)')

        # 4. Check for random-looking character sequences
        # Look for patterns like "xjkqz" - uncommon letter combinations
        uncommon_patterns = ['xj', 'qz', 'xz', 'qx', 'zx', 'jq', 'vx', 'wx']
        uncommon_found = sum(1 for pattern in uncommon_patterns if pattern in domain.lower())
        if uncommon_found >= 2:
            garbage_score += 20
            reasons.append('Uncommon letter combinations detected')

        # 5. Check for excessive hyphens or underscores
        special_ratio = (domain.count('-') + domain.count('_')) / len(domain) if len(domain) > 0 else 0
        if special_ratio > 0.3:
            garbage_score += 15
            reasons.append('Excessive hyphens/underscores')

        # 6. Check length vs readable words
        # Try to find recognizable English word patterns
        word_like_parts = re.findall(r'[a-z]{3,}', domain.lower())
        if len(domain) > 10 and not word_like_parts:
            garbage_score += 15
            reasons.append('Long domain with no recognizable words')

        # 7. Check for keyboard mashing patterns (adjacent keys)
        keyboard_patterns = ['asdf', 'qwer', 'zxcv', 'hjkl', 'dfgh', 'jklm']
        if any(pattern in domain.lower() for pattern in keyboard_patterns):
            garbage_score += 35
            reasons.append('Keyboard mashing pattern detected')

        # 8. Entropy check (randomness)
        entropy = self._calculate_entropy(domain)
        if entropy > 4.0:  # High entropy = very random
            garbage_score += 10
            reasons.append(f'High randomness (entropy: {entropy:.2f})')

        is_likely_garbage = garbage_score >= 50
        confidence = min(garbage_score / 100, 1.0)

        return {
            'is_likely_garbage': is_likely_garbage,
            'confidence': confidence,
            'garbage_score': garbage_score,
            'reasons': reasons
        }

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        from collections import Counter
        import math
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _check_dns_existence(self, domain: str) -> Dict:
        """
        Check if domain exists on the internet via DNS lookup
        This is the KEY check that determines if URL is real!
        """
        result = {
            'exists': False,
            'has_a_record': False,
            'has_mx_record': False,
            'has_ns_record': False,
            'ip_addresses': [],
            'mx_servers': [],
            'name_servers': [],
            'error': None,
            'response_time': None
        }

        if not domain:
            result['error'] = 'Empty domain'
            return result

        start_time = time.time()

        try:
            # Try A record (IPv4 address)
            try:
                answers = self.resolver.resolve(domain, 'A')
                result['has_a_record'] = True
                result['ip_addresses'] = [str(rdata) for rdata in answers]
                result['exists'] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except dns.exception.Timeout:
                result['error'] = 'DNS timeout'

            # Try AAAA record (IPv6 address)
            if not result['has_a_record']:
                try:
                    answers = self.resolver.resolve(domain, 'AAAA')
                    result['has_a_record'] = True
                    result['ip_addresses'] = [str(rdata) for rdata in answers]
                    result['exists'] = True
                except:
                    pass

            # Try MX record (mail servers)
            try:
                answers = self.resolver.resolve(domain, 'MX')
                result['has_mx_record'] = True
                result['mx_servers'] = [str(rdata.exchange) for rdata in answers]
                result['exists'] = True
            except:
                pass

            # Try NS record (name servers)
            try:
                answers = self.resolver.resolve(domain, 'NS')
                result['has_ns_record'] = True
                result['name_servers'] = [str(rdata) for rdata in answers]
                result['exists'] = True
            except:
                pass

            result['response_time'] = time.time() - start_time

        except dns.resolver.NXDOMAIN:
            result['error'] = 'Domain does not exist (NXDOMAIN)'
            result['exists'] = False
        except dns.resolver.NoNameservers:
            result['error'] = 'No nameservers found'
            result['exists'] = False
        except dns.exception.Timeout:
            result['error'] = 'DNS query timeout'
        except Exception as e:
            result['error'] = f'DNS error: {str(e)}'

        return result

    def _check_whois_info(self, domain: str) -> Dict:
        """
        Check WHOIS information for domain
        Provides registration date, registrar, etc.
        """
        result = {
            'available': False,
            'registered': False,
            'creation_date': None,
            'expiration_date': None,
            'registrar': None,
            'domain_age_days': None,
            'error': None
        }

        try:
            w = whois.whois(domain)

            if w.domain_name:
                result['available'] = True
                result['registered'] = True

                # Creation date
                if w.creation_date:
                    if isinstance(w.creation_date, list):
                        creation = w.creation_date[0]
                    else:
                        creation = w.creation_date
                    result['creation_date'] = str(creation)

                    # Calculate age
                    if isinstance(creation, datetime):
                        age = (datetime.now() - creation).days
                        result['domain_age_days'] = age

                # Expiration date
                if w.expiration_date:
                    if isinstance(w.expiration_date, list):
                        expiration = w.expiration_date[0]
                    else:
                        expiration = w.expiration_date
                    result['expiration_date'] = str(expiration)

                # Registrar
                if w.registrar:
                    result['registrar'] = w.registrar

        except Exception as e:
            result['error'] = str(e)
            result['available'] = False

        return result

    def _check_ip_reputation(self, ip_addresses: list) -> Dict:
        """Check IP address reputation"""
        result = {
            'clean': True,
            'suspicious_ips': [],
            'details': []
        }

        for ip in ip_addresses:
            # Check if IP is in private range (suspicious for public URLs)
            if self._is_private_ip(ip):
                result['clean'] = False
                result['suspicious_ips'].append(ip)
                result['details'].append(f'{ip} is a private IP address (not publicly accessible)')

        return result

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False

            first = int(parts[0])
            second = int(parts[1])

            # Private ranges
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:  # Localhost
                return True

            return False
        except:
            return False

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IPv4 address"""
        try:
            socket.inet_aton(ip)
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False

    def _determine_final_classification(self, result: Dict) -> Dict:
        """Determine final classification and recommendation"""
        issues = result['issues']
        is_on_internet = result['is_on_internet']
        is_random_garbage = result['is_random_garbage']

        # Classification logic
        if is_random_garbage and not is_on_internet:
            result['classification'] = 'RANDOM_GARBAGE_NOT_ON_INTERNET'
            result['recommendation'] = '⚠️ This appears to be random gibberish and does NOT exist on the internet. Cannot be accessed.'
            result['threat_level'] = 10
            result['confidence'] = 0.95

        elif not is_on_internet and not is_random_garbage:
            result['classification'] = 'NOT_ON_INTERNET'
            result['recommendation'] = '⚠️ This domain does NOT exist on the internet (no DNS records found). Based on characteristics, it could be phishing or fake.'
            result['threat_level'] = 60
            result['confidence'] = 0.90

            # Analyze characteristics to determine phishing likelihood
            domain_info = result['details']['domain_info']
            tld_check = result['details']['tld_check']

            phishing_indicators = 0
            if tld_check['category'] == 'free_suspicious':
                phishing_indicators += 1
                issues.append('Uses suspicious free TLD')

            # Check for brand names in non-existent domain
            common_brands = ['paypal', 'google', 'amazon', 'microsoft', 'apple', 'bank']
            domain_lower = domain_info['domain'].lower()
            if any(brand in domain_lower for brand in common_brands):
                phishing_indicators += 2
                issues.append('Contains brand name but domain does not exist')
                result['threat_level'] = 90
                result['recommendation'] = '🚨 HIGH THREAT: Domain impersonates a brand but does NOT exist on internet. Likely PHISHING attempt!'

        elif is_on_internet and is_random_garbage:
            result['classification'] = 'EXISTS_BUT_SUSPICIOUS'
            result['recommendation'] = '⚠️ Domain EXISTS on internet but has random/garbage appearance. Proceed with extreme caution!'
            result['threat_level'] = 70
            result['confidence'] = 0.75

        elif is_on_internet and not is_random_garbage:
            result['classification'] = 'REAL_DOMAIN_EXISTS'
            result['recommendation'] = '✓ Domain EXISTS on the internet with valid DNS records. Proceeding with phishing analysis...'
            result['threat_level'] = 0  # Will be determined by phishing analysis
            result['confidence'] = 0.85

            # Check domain age for additional context
            whois_check = result['details'].get('whois_check', {})
            if whois_check.get('domain_age_days'):
                age = whois_check['domain_age_days']
                if age < 30:
                    issues.append(f'Very new domain (created {age} days ago) - higher phishing risk')
                    result['threat_level'] = 40
                elif age < 180:
                    issues.append(f'Relatively new domain ({age} days old)')
                    result['threat_level'] = 20

        else:
            result['classification'] = 'UNKNOWN'
            result['recommendation'] = 'Unable to fully classify this URL. Manual review recommended.'
            result['threat_level'] = 50
            result['confidence'] = 0.50

        return result


if __name__ == '__main__':
    # Test the validator
    validator = AdvancedDomainValidator()

    test_urls = [
        'https://www.google.com',
        'http://xjkqzwxyz.tk',
        'https://secure-login-paypal.ml',
        'http://asdfghjkl123456.com',
        'https://thisisnotarealdomain12345xyz.com',
        'http://192.168.1.1',
        'hxxp://malicious-garbage-url.xyz'
    ]

    print("=" * 80)
    print("ADVANCED DOMAIN VALIDATOR TEST")
    print("=" * 80)

    for url in test_urls:
        print(f"\nURL: {url}")
        result = validator.validate_url_comprehensive(url)
        print(f"Classification: {result['classification']}")
        print(f"On Internet: {result['is_on_internet']}")
        print(f"Random Garbage: {result['is_random_garbage']}")
        print(f"Threat Level: {result['threat_level']}/100")
        print(f"Recommendation: {result['recommendation']}")
        if result['issues']:
            print(f"Issues: {', '.join(result['issues'][:3])}")
        print("-" * 80)
