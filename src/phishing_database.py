"""
Built-in Phishing Database - No API Key Required
Contains known phishing patterns, domains, and URL signatures
Updated with common phishing indicators from security research
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import hashlib


class PhishingDatabase:
    """
    Local phishing detection database - no external API needed
    Uses pattern matching, known malicious domains, and heuristics
    """

    def __init__(self):
        # Known phishing domain patterns (regex)
        self.phishing_patterns = self._load_phishing_patterns()

        # Known malicious domains/substrings
        self.malicious_domains = self._load_malicious_domains()

        # Suspicious TLDs commonly used in phishing
        self.suspicious_tlds = self._load_suspicious_tlds()

        # Known phishing URL hashes (SHA256 of normalized URLs)
        self.known_phishing_hashes = self._load_known_hashes()

        # Brand impersonation patterns
        self.brand_patterns = self._load_brand_patterns()

        # Phishing keyword combinations
        self.phishing_keywords = self._load_phishing_keywords()

    def _load_phishing_patterns(self) -> List[re.Pattern]:
        """Load regex patterns for known phishing URL structures"""
        patterns = [
            # Login/verify/account patterns with brand names
            r'(paypal|apple|microsoft|google|amazon|netflix|facebook|instagram|bank|chase|wellsfargo)[-.]*(login|verify|secure|account|update|confirm)',
            r'(login|verify|secure|account|update|confirm)[-.]*(paypal|apple|microsoft|google|amazon|netflix|facebook|instagram|bank)',

            # Suspicious subdomains mimicking brands
            r'^(www\.)?(paypal|apple|microsoft|google|amazon|netflix|bank)\.[a-z]{2,10}\.(com|net|org|info|xyz|tk|ml|ga|cf|gq)',

            # IP address URLs with paths
            r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.*(login|account|verify|secure|bank|paypal)',

            # Data URI phishing
            r'^data:text/html',

            # Suspicious URL structures
            r'@.*\.(com|net|org)',  # @ symbol in URL (redirect trick)
            r'https?://[^/]*\.(tk|ml|ga|cf|gq|xyz|top|work|click|link|surf)/.*(login|account|secure)',

            # Double extensions
            r'\.(html|php|asp)\.(html|php|asp|exe|zip)',

            # Encoded characters abuse
            r'%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}.*login',

            # Long random subdomains
            r'[a-z0-9]{20,}\.(com|net|org)',

            # Punycode domains (internationalized domain names abuse)
            r'xn--[a-z0-9]+',

            # Common phishing path patterns
            r'/wp-(admin|content|includes)/.*\.(php|html)\?.*=',
            r'/\.well-known/.*\.(html|php)',
            r'/(cgi-bin|tmp|temp)/.*\.(php|html)',
        ]
        return [re.compile(p, re.IGNORECASE) for p in patterns]

    def _load_malicious_domains(self) -> set:
        """Load known malicious domain substrings"""
        return {
            # Typosquatting variations
            'paypa1', 'paypal-secure', 'paypal-login', 'paypal-verify',
            'paypai', 'paypaI', 'paylpal', 'paypall', 'payp4l',
            'arnazon', 'amaz0n', 'amazom', 'amazon-secure', 'amazon-login',
            'arnazon', 'amaz0n', 'amazonsecurity', 'amazon-verify',
            'micros0ft', 'mircosoft', 'microsoft-login', 'microsoft-verify',
            'microsoftonline-login', 'office365-login', 'outlook-verify',
            'g00gle', 'googie', 'google-verify', 'google-secure', 'google-login',
            'gooogle', 'g0ogle', 'googlesecurity',
            'faceb00k', 'facebok', 'facebook-login', 'facebook-verify',
            'faceboook', 'facebk', 'fb-login', 'fb-verify',
            'app1e', 'appie', 'apple-verify', 'apple-id-login', 'icloud-login',
            'appleid-secure', 'apple-support-verify',
            'netfllx', 'netf1ix', 'netflix-login', 'netflix-verify', 'netflix-payment',
            'netflx', 'netflix-update', 'netflix-secure',
            'lnstagram', 'instagran', 'instagram-verify', 'instagram-login',
            'instaqram', 'lnstaqram',
            'linkedln', 'linkdin', 'linkedin-verify', 'linkedin-login',
            'linkedn', 'linked1n',
            'dropb0x', 'dropbox-login', 'dropbox-verify',
            'wells-fargo', 'wellsfargo-login', 'wellsfargo-verify',
            'bankofamerica-login', 'boa-secure', 'bofa-verify',
            'chase-login', 'chase-verify', 'chase-secure',
            'citibank-login', 'citi-verify', 'citibank-secure',
            'usbank-login', 'usbank-verify',
            'capitalone-login', 'capital0ne',

            # Known malicious domain suffixes
            'secure-login', 'verify-account', 'update-info', 'confirm-identity',
            'security-check', 'account-verify', 'login-secure', 'auth-verify',
            'wallet-verify', 'payment-update', 'billing-verify',

            # Cryptocurrency scams
            'bitcoin-verify', 'crypto-wallet', 'eth-airdrop', 'btc-giveaway',
            'coinbase-verify', 'binance-login', 'metamask-verify',

            # Government impersonation
            'irs-refund', 'irs-verify', 'ssa-verify', 'dmv-renew',
            'stimulus-check', 'tax-refund-verify',

            # Delivery scams
            'usps-delivery', 'fedex-tracking', 'ups-delivery', 'dhl-package',
            'amazon-delivery', 'shipping-verify',
        }

    def _load_suspicious_tlds(self) -> set:
        """TLDs frequently abused in phishing"""
        return {
            # Free/cheap TLDs often abused
            'tk', 'ml', 'ga', 'cf', 'gq',  # Freenom TLDs
            'xyz', 'top', 'work', 'click', 'link',
            'surf', 'club', 'site', 'online', 'live',
            'icu', 'buzz', 'fun', 'space', 'monster',
            'cam', 'rest', 'fit', 'quest', 'beauty',

            # Country codes often abused
            'ru', 'cn', 'su', 'cc', 'ws', 'to',
            'pw', 'nu', 'me.uk', 'co.uk',

            # New gTLDs used in phishing
            'support', 'help', 'services', 'security',
            'center', 'verify', 'login', 'account',
        }

    def _load_known_hashes(self) -> set:
        """SHA256 hashes of known phishing URLs (normalized)"""
        # This would be populated from threat intelligence feeds
        # For now, return empty set - can be extended
        return set()

    def _load_brand_patterns(self) -> Dict[str, List[str]]:
        """Brand names and their common misspellings/variations"""
        return {
            'paypal': ['paypa1', 'paypai', 'paypaI', 'paylpal', 'paypall', 'payp4l', 'pay-pal', 'paypol'],
            'amazon': ['arnazon', 'amaz0n', 'amazom', 'amzon', 'amazn', 'arnazon', 'amaazon'],
            'microsoft': ['micros0ft', 'mircosoft', 'microsft', 'mlcrosoft', 'micr0soft'],
            'google': ['g00gle', 'googie', 'gooogle', 'g0ogle', 'googel', 'qoogle'],
            'facebook': ['faceb00k', 'facebok', 'faceboook', 'facebk', 'facbook', 'fac3book'],
            'apple': ['app1e', 'appie', 'aple', 'applle', 'appl3', 'appie'],
            'netflix': ['netfllx', 'netf1ix', 'netflx', 'neflix', 'netfiix', 'n3tflix'],
            'instagram': ['lnstagram', 'instagran', 'instaqram', 'lnstaqram', 'instragram'],
            'linkedin': ['linkedln', 'linkdin', 'linkedn', 'linked1n', 'llnkedin'],
            'twitter': ['twltter', 'twiter', 'twtter', 'tw1tter', 'tvvitter'],
            'whatsapp': ['whatsap', 'watsapp', 'whatsaap', 'whatssapp', 'whats4pp'],
            'dropbox': ['dropb0x', 'dr0pbox', 'dropbok', 'dropboks'],
            'chase': ['chas3', 'chasse', 'cbase'],
            'wellsfargo': ['wells-fargo', 'wellsfarg0', 'we11sfargo'],
            'bankofamerica': ['bankofamerica', 'bank0famerica', 'bankofamerrica'],
            'citibank': ['c1tibank', 'citibenk', 'citlbank'],
            'coinbase': ['c0inbase', 'coinbas3', 'colnbase'],
            'binance': ['blnance', 'b1nance', 'binanse'],
        }

    def _load_phishing_keywords(self) -> List[Tuple[str, float]]:
        """Keywords and their risk scores"""
        return [
            # High risk keywords (score 0.8-1.0)
            ('verify-your-account', 0.9),
            ('confirm-identity', 0.9),
            ('suspended-account', 0.95),
            ('unusual-activity', 0.85),
            ('security-alert', 0.8),
            ('update-payment', 0.85),
            ('expire-soon', 0.8),
            ('verify-now', 0.85),
            ('confirm-now', 0.85),
            ('urgent-action', 0.9),
            ('immediate-action', 0.9),
            ('account-locked', 0.9),
            ('password-reset', 0.7),
            ('signin-attempt', 0.75),
            ('unauthorized-access', 0.85),

            # Medium risk keywords (score 0.5-0.79)
            ('login', 0.5),
            ('signin', 0.5),
            ('secure', 0.5),
            ('verify', 0.6),
            ('confirm', 0.6),
            ('account', 0.4),
            ('update', 0.5),
            ('billing', 0.6),
            ('payment', 0.6),
            ('wallet', 0.6),
            ('recover', 0.6),
            ('restore', 0.6),
            ('unlock', 0.7),
            ('reactivate', 0.7),

            # Crypto-related (high risk)
            ('airdrop', 0.8),
            ('giveaway', 0.75),
            ('free-crypto', 0.9),
            ('claim-reward', 0.85),
            ('connect-wallet', 0.7),
        ]

    def check_url(self, url: str) -> Dict:
        """
        Check URL against phishing database
        Returns detection result with confidence and reasons
        """
        result = {
            'url': url,
            'is_phishing': False,
            'confidence': 0.0,
            'risk_score': 0,
            'detection_method': None,
            'reasons': [],
            'matched_patterns': [],
            'brand_impersonation': None,
        }

        try:
            parsed = urlparse(url.lower())
            domain = parsed.netloc
            path = parsed.path
            full_url = url.lower()

            risk_score = 0
            reasons = []

            # 1. Check against regex patterns
            for pattern in self.phishing_patterns:
                if pattern.search(full_url):
                    risk_score += 30
                    reasons.append(f'Matches phishing pattern: {pattern.pattern[:50]}...')
                    result['matched_patterns'].append(pattern.pattern)

            # 2. Check for malicious domain substrings
            for mal_domain in self.malicious_domains:
                if mal_domain in domain or mal_domain in full_url:
                    risk_score += 40
                    reasons.append(f'Contains known malicious pattern: {mal_domain}')

            # 3. Check suspicious TLD
            tld = domain.split('.')[-1] if '.' in domain else ''
            if tld in self.suspicious_tlds:
                risk_score += 15
                reasons.append(f'Uses suspicious TLD: .{tld}')

            # 4. Brand impersonation check
            brand_found = self._check_brand_impersonation(domain, full_url)
            if brand_found:
                result['brand_impersonation'] = brand_found
                risk_score += 35
                reasons.append(f'Possible brand impersonation: {brand_found["brand"]}')

            # 5. Keyword analysis
            keyword_score = self._analyze_keywords(full_url)
            if keyword_score > 0:
                risk_score += int(keyword_score * 20)
                reasons.append(f'Contains suspicious keywords (score: {keyword_score:.2f})')

            # 6. URL structure analysis
            structure_flags = self._analyze_url_structure(url, parsed)
            risk_score += structure_flags['score']
            reasons.extend(structure_flags['reasons'])

            # 7. Check hash against known phishing
            url_hash = self._hash_url(url)
            if url_hash in self.known_phishing_hashes:
                risk_score = 100
                reasons.append('URL matches known phishing database')

            # Calculate final result
            result['risk_score'] = min(100, risk_score)
            result['confidence'] = min(1.0, risk_score / 100)
            result['reasons'] = reasons

            # Determine if phishing
            if risk_score >= 70:
                result['is_phishing'] = True
                result['detection_method'] = 'high_confidence_match'
            elif risk_score >= 50:
                result['is_phishing'] = True
                result['detection_method'] = 'medium_confidence_match'
            elif risk_score >= 30:
                result['is_phishing'] = None  # Suspicious but uncertain
                result['detection_method'] = 'suspicious_indicators'
            else:
                result['is_phishing'] = False
                result['detection_method'] = 'no_match'

        except Exception as e:
            result['error'] = str(e)

        return result

    def _check_brand_impersonation(self, domain: str, full_url: str) -> Optional[Dict]:
        """Check for brand impersonation attempts"""
        for brand, variations in self.brand_patterns.items():
            # Check if misspelling is in domain
            for var in variations:
                if var in domain:
                    # Verify it's not the real domain
                    real_domains = {
                        'paypal': 'paypal.com',
                        'amazon': 'amazon.com',
                        'microsoft': 'microsoft.com',
                        'google': 'google.com',
                        'facebook': 'facebook.com',
                        'apple': 'apple.com',
                        'netflix': 'netflix.com',
                        'instagram': 'instagram.com',
                        'linkedin': 'linkedin.com',
                        'twitter': 'twitter.com',
                        'chase': 'chase.com',
                    }
                    real = real_domains.get(brand, f'{brand}.com')
                    if real not in domain:
                        return {
                            'brand': brand,
                            'variation': var,
                            'real_domain': real
                        }

            # Check if brand name is in suspicious context
            if brand in domain:
                # Check if it's a subdomain of a different domain
                parts = domain.split('.')
                if len(parts) > 2:
                    # Brand as subdomain (e.g., paypal.malicious.com)
                    main_domain = '.'.join(parts[-2:])
                    real_domains = {
                        'paypal': 'paypal.com',
                        'amazon': 'amazon.com',
                        'microsoft': 'microsoft.com',
                        'google': 'google.com',
                    }
                    real = real_domains.get(brand)
                    if real and main_domain != real:
                        return {
                            'brand': brand,
                            'variation': f'{brand} as subdomain',
                            'real_domain': real
                        }

        return None

    def _analyze_keywords(self, url: str) -> float:
        """Analyze URL for phishing keywords"""
        total_score = 0
        max_score = 0

        for keyword, score in self.phishing_keywords:
            if keyword in url:
                total_score += score
                max_score = max(max_score, score)

        # Return weighted score
        if total_score > 0:
            return min(1.0, (total_score * 0.3) + (max_score * 0.7))
        return 0

    def _analyze_url_structure(self, url: str, parsed) -> Dict:
        """Analyze URL structure for suspicious patterns"""
        flags = {'score': 0, 'reasons': []}

        domain = parsed.netloc
        path = parsed.path

        # Check for IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            flags['score'] += 25
            flags['reasons'].append('Uses IP address instead of domain')

        # Check for @ symbol (URL obfuscation)
        if '@' in url:
            flags['score'] += 30
            flags['reasons'].append('Contains @ symbol (possible URL obfuscation)')

        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            flags['score'] += 15
            flags['reasons'].append(f'Excessive subdomains ({subdomain_count})')

        # Check for very long domain
        if len(domain) > 50:
            flags['score'] += 10
            flags['reasons'].append('Unusually long domain name')

        # Check for random-looking strings
        if re.search(r'[a-z0-9]{15,}', domain):
            flags['score'] += 20
            flags['reasons'].append('Contains random-looking character sequence')

        # Check for suspicious path patterns
        if re.search(r'/(wp-|cgi-bin|tmp|temp)/', path):
            flags['score'] += 15
            flags['reasons'].append('Suspicious path pattern')

        # Check for multiple file extensions
        if re.search(r'\.[a-z]{2,4}\.[a-z]{2,4}$', path):
            flags['score'] += 20
            flags['reasons'].append('Multiple file extensions detected')

        # Check for port number (unusual for legitimate sites)
        if ':' in domain and not domain.endswith(':443') and not domain.endswith(':80'):
            flags['score'] += 15
            flags['reasons'].append('Uses non-standard port')

        # Check for homograph characters (simplified)
        if any(ord(c) > 127 for c in domain):
            flags['score'] += 25
            flags['reasons'].append('Contains non-ASCII characters (possible homograph attack)')

        # Check for URL shortener (sometimes used to hide phishing)
        shorteners = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'}
        if any(s in domain for s in shorteners):
            flags['score'] += 10
            flags['reasons'].append('URL shortener detected (destination hidden)')

        return flags

    def _hash_url(self, url: str) -> str:
        """Generate SHA256 hash of normalized URL"""
        # Normalize URL
        normalized = url.lower().strip()
        if normalized.endswith('/'):
            normalized = normalized[:-1]
        return hashlib.sha256(normalized.encode()).hexdigest()

    def get_stats(self) -> Dict:
        """Get database statistics"""
        return {
            'phishing_patterns': len(self.phishing_patterns),
            'malicious_domains': len(self.malicious_domains),
            'suspicious_tlds': len(self.suspicious_tlds),
            'known_hashes': len(self.known_phishing_hashes),
            'brand_patterns': len(self.brand_patterns),
            'keywords': len(self.phishing_keywords),
        }


# Singleton instance
_database_instance = None

def get_phishing_database() -> PhishingDatabase:
    """Get singleton phishing database instance"""
    global _database_instance
    if _database_instance is None:
        _database_instance = PhishingDatabase()
    return _database_instance


if __name__ == '__main__':
    # Test the database
    db = PhishingDatabase()

    print("Phishing Database Statistics:")
    print("-" * 40)
    stats = db.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print("\n" + "=" * 60)
    print("Testing URLs:")
    print("=" * 60)

    test_urls = [
        # Known phishing patterns
        'http://paypal-verify-account.malicious.xyz/login.php',
        'http://amazon-security-check.tk/update',
        'http://192.168.1.1/paypal/login.html',
        'http://www.google.verify-account.com/signin',
        'http://faceb00k-login.ml/auth',
        'http://netflix-update-payment.xyz/billing',
        'http://app1e-id-verify.cf/confirm',
        'http://micros0ft-office365-login.ga/secure',

        # Legitimate URLs (should pass)
        'https://www.google.com',
        'https://www.paypal.com/signin',
        'https://www.amazon.com/ap/signin',
        'https://login.microsoft.com',
        'https://www.facebook.com/login',
        'https://www.netflix.com/login',
        'https://github.com',
        'https://stackoverflow.com',
    ]

    for url in test_urls:
        result = db.check_url(url)
        status = "PHISHING" if result['is_phishing'] else "SUSPICIOUS" if result['is_phishing'] is None else "SAFE"
        print(f"\n[{status}] {url[:60]}...")
        print(f"   Risk Score: {result['risk_score']}/100")
        print(f"   Confidence: {result['confidence']:.2%}")
        if result['reasons']:
            print(f"   Reasons: {', '.join(result['reasons'][:2])}")
        if result['brand_impersonation']:
            print(f"   Brand: {result['brand_impersonation']['brand']}")
