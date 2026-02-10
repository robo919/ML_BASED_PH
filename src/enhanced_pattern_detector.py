"""
Enhanced Pattern Detection for Phishing URLs
Catches obvious phishing patterns that ML models might miss
"""

import re
from urllib.parse import urlparse
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EnhancedPatternDetector:
    """
    Advanced pattern-based phishing detection
    Catches obvious phishing that ML might miss
    """

    def __init__(self):
        # Major brands that are commonly impersonated
        self.brands = [
            'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
            'netflix', 'instagram', 'twitter', 'linkedin', 'ebay', 'yahoo',
            'wellsfargo', 'wells-fargo', 'chase', 'bankofamerica', 'citibank', 'hsbc',
            'dropbox', 'adobe', 'spotify', 'whatsapp', 'telegram', 'outlook',
            'office365', 'gmail', 'icloud', 'docusign', 'fedex', 'dhl', 'ups'
        ]

        # Suspicious subdomain keywords
        self.suspicious_subdomains = [
            'secure', 'login', 'signin', 'account', 'verify', 'update',
            'confirm', 'auth', 'banking', 'webmail', 'support', 'helpdesk',
            'admin', 'manager', 'portal', 'service', 'customer', 'billing'
        ]

        # High-risk phishing keywords (weighted)
        self.phishing_keywords = {
            # Authentication/Access (HIGH RISK)
            'login': 3, 'signin': 3, 'sign-in': 3, 'log-in': 3,
            'auth': 3, 'authenticate': 3, 'authentication': 3,
            'sso': 3, 'portal': 2, 'access': 2,

            # Security/Verification (CRITICAL)
            'verify': 5, 'verification': 5, 'validate': 4, 'validation': 4,
            'confirm': 4, 'confirmation': 4, 'secure': 4, 'security': 3,
            'protected': 3, 'safety': 3, 'ssl': 3,

            # Account Management (HIGH RISK)
            'account': 4, 'password': 5, 'reset': 4, 'recovery': 4,
            'restore': 3, 'unlock': 4, 'suspended': 5, 'blocked': 5,
            'disabled': 4, 'locked': 4, 'freeze': 4,

            # Urgency/Action (CRITICAL)
            'urgent': 5, 'immediate': 5, 'action': 4, 'required': 4,
            'expires': 4, 'expiring': 4, 'limited': 4, 'warning': 4,
            'alert': 4, 'notice': 3, 'important': 3,

            # Financial (HIGH RISK)
            'billing': 4, 'payment': 4, 'invoice': 3, 'transaction': 3,
            'wallet': 3, 'card': 3, 'bank': 4, 'finance': 3,

            # Updates (MEDIUM RISK)
            'update': 3, 'upgrade': 3, 'renew': 3, 'refresh': 2,
            'sync': 2, 'activate': 3, 'setup': 2,

            # Support (MEDIUM RISK)
            'support': 2, 'help': 2, 'service': 2, 'customer': 2,
            'contact': 2, 'info': 2, 'information': 2
        }

        # Suspicious TLDs (weighted by abuse level)
        self.suspicious_tlds = {
            # Free domains (very high abuse)
            '.tk': 5, '.ml': 5, '.ga': 5, '.cf': 5, '.gq': 5,

            # Cheap domains (high abuse)
            '.xyz': 4, '.top': 4, '.work': 4, '.click': 4, '.link': 4,
            '.online': 4, '.site': 4, '.website': 4, '.space': 4,

            # Generic (medium abuse)
            '.info': 3, '.biz': 3, '.pw': 3, '.cc': 3,

            # Country codes sometimes abused
            '.ru': 2, '.cn': 2, '.br': 2,
        }

        # Suspicious patterns in domain
        self.suspicious_patterns = [
            (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'IP address instead of domain', 10),  # Increased from 5
            (r'xn--', 'Punycode encoding', 4),
            (r'-{2,}', 'Multiple consecutive hyphens', 3),
            (r'\d{5,}', 'Long number sequence', 3),
            (r'([a-z])\1{3,}', 'Repeated characters', 2),
        ]

    def analyze_url(self, url: str) -> Dict:
        """
        Comprehensive pattern analysis of URL

        Returns:
            Dict with risk_score, is_suspicious, reasons, and details
        """
        parsed = urlparse(url.lower())
        domain = parsed.netloc
        path = parsed.path
        full_url = url.lower()

        risk_score = 0
        reasons = []
        details = {
            'brand_detected': None,
            'phishing_keywords': [],
            'suspicious_patterns': [],
            'tld_risk': 0,
            'domain_structure_risk': 0
        }

        # 1. Check for brand impersonation in domain
        brand_risk, brand_name = self._check_brand_impersonation(domain, path)
        if brand_risk > 0:
            risk_score += brand_risk
            details['brand_detected'] = brand_name
            reasons.append(f"Brand '{brand_name}' detected in suspicious context")

        # 2. Check for phishing keywords
        keyword_risk, found_keywords = self._check_phishing_keywords(full_url)
        if keyword_risk > 0:
            risk_score += keyword_risk
            details['phishing_keywords'] = found_keywords
            if len(found_keywords) >= 3:
                risk_score += 10  # Bonus for multiple keywords
                reasons.append(f"Multiple phishing keywords: {', '.join(found_keywords[:3])}")
            elif found_keywords:
                reasons.append(f"Phishing keywords detected: {', '.join(found_keywords[:2])}")

        # 3. Check suspicious domain structure
        structure_risk, structure_reasons = self._check_domain_structure(domain)
        if structure_risk > 0:
            risk_score += structure_risk
            details['domain_structure_risk'] = structure_risk
            reasons.extend(structure_reasons)

        # 4. Check TLD
        tld_risk, tld = self._check_tld(domain)
        if tld_risk > 0:
            risk_score += tld_risk
            details['tld_risk'] = tld_risk
            reasons.append(f"Suspicious TLD: {tld}")

        # 5. Check for suspicious patterns
        pattern_risk, pattern_matches = self._check_suspicious_patterns(full_url)
        if pattern_risk > 0:
            risk_score += pattern_risk
            details['suspicious_patterns'] = pattern_matches
            for match in pattern_matches:
                reasons.append(match)

        # 6. Check for HTTP (no HTTPS)
        http_risk, http_reason = self._check_http_usage(parsed)
        if http_risk > 0:
            risk_score += http_risk
            if http_reason:
                reasons.append(http_reason)

        # 7. Check suspicious subdomains
        subdomain_risk, subdomain_reasons = self._check_suspicious_subdomains(domain, brand_name)
        if subdomain_risk > 0:
            risk_score += subdomain_risk
            reasons.extend(subdomain_reasons)

        # 8. Check for URL shorteners
        shortener_risk, shortener_reason = self._check_url_shorteners(domain)
        if shortener_risk > 0:
            risk_score += shortener_risk
            if shortener_reason:
                reasons.append(shortener_reason)

        # 9. Check for suspicious path patterns
        path_risk, path_reasons = self._check_suspicious_path(path, brand_name)
        if path_risk > 0:
            risk_score += path_risk
            reasons.extend(path_reasons)

        # 10. Check for obvious phishing combinations
        combination_risk, combo_reasons = self._check_dangerous_combinations(
            domain, brand_name, found_keywords, tld_risk
        )
        if combination_risk > 0:
            risk_score += combination_risk
            reasons.extend(combo_reasons)

        # Determine verdict
        is_suspicious = risk_score >= 15  # Lower threshold for better detection

        return {
            'risk_score': min(risk_score, 100),  # Cap at 100
            'is_suspicious': is_suspicious,
            'confidence': min(risk_score / 50, 1.0),  # 0-1 scale
            'reasons': reasons[:5],  # Top 5 reasons
            'details': details,
            'verdict': self._get_verdict(risk_score)
        }

    def _check_brand_impersonation(self, domain: str, path: str) -> Tuple[int, str]:
        """Check if brand name appears in suspicious context"""
        risk = 0
        found_brand = None

        for brand in self.brands:
            if brand in domain or brand in path:
                found_brand = brand

                # High risk: brand in subdomain with other words
                if brand in domain and domain != f"{brand}.com" and domain != f"www.{brand}.com":
                    # Check if brand is combined with phishing keywords
                    if any(keyword in domain for keyword in ['login', 'verify', 'secure', 'auth', 'account']):
                        risk += 25  # CRITICAL - brand + phishing keyword in domain
                    elif '-' in domain and brand in domain.split('.')[0]:
                        risk += 20  # HIGH - brand with hyphens (e.g., login-paypal)
                    elif brand in domain.split('.')[0]:
                        risk += 15  # MEDIUM - brand in subdomain

                    # Check if it's not the official domain
                    official_domains = [
                        f"{brand}.com", f"www.{brand}.com",
                        f"{brand}.co.uk", f"{brand}.net", f"{brand}.org"
                    ]
                    if domain not in official_domains:
                        risk += 10  # Not official domain

                break

        return risk, found_brand

    def _check_phishing_keywords(self, url: str) -> Tuple[int, List[str]]:
        """Check for phishing keywords with weighted scoring"""
        risk = 0
        found = []

        for keyword, weight in self.phishing_keywords.items():
            if keyword in url:
                risk += weight
                found.append(keyword)

        return risk, found

    def _check_domain_structure(self, domain: str) -> Tuple[int, List[str]]:
        """Analyze domain structure for suspicious patterns"""
        risk = 0
        reasons = []

        # Count subdomains
        parts = domain.split('.')
        if len(parts) > 3:
            risk += 5
            reasons.append(f"Too many subdomains ({len(parts) - 2})")

        # Check for excessive hyphens
        hyphen_count = domain.count('-')
        if hyphen_count >= 3:
            risk += hyphen_count * 3
            reasons.append(f"Excessive hyphens ({hyphen_count})")
        elif hyphen_count >= 2:
            risk += hyphen_count * 2

        # Check domain length
        main_domain = parts[0] if parts else domain
        if len(main_domain) > 30:
            risk += 5
            reasons.append(f"Very long domain name ({len(main_domain)} chars)")

        # Check for number-letter mixing
        if re.search(r'[a-z]\d|\d[a-z]', main_domain):
            if not any(brand in main_domain for brand in self.brands):
                risk += 3
                reasons.append("Suspicious number-letter mixing")

        return risk, reasons

    def _check_tld(self, domain: str) -> Tuple[int, str]:
        """Check TLD risk level"""
        for tld, risk in self.suspicious_tlds.items():
            if domain.endswith(tld):
                return risk, tld
        return 0, ''

    def _check_suspicious_patterns(self, url: str) -> Tuple[int, List[str]]:
        """Check for known suspicious patterns"""
        risk = 0
        matches = []

        for pattern, description, pattern_risk in self.suspicious_patterns:
            if re.search(pattern, url):
                risk += pattern_risk
                matches.append(description)

        return risk, matches

    def _check_dangerous_combinations(self, domain: str, brand: str,
                                     keywords: List[str], tld_risk: int) -> Tuple[int, List[str]]:
        """Check for dangerous combinations that indicate phishing"""
        risk = 0
        reasons = []

        # CRITICAL: Brand + multiple phishing keywords + suspicious TLD
        if brand and len(keywords) >= 2 and tld_risk >= 3:
            risk += 30
            reasons.append("CRITICAL: Brand impersonation with phishing keywords on suspicious TLD")

        # HIGH: Brand + auth keywords
        auth_keywords = {'login', 'signin', 'auth', 'verify', 'account', 'password'}
        if brand and any(k in keywords for k in auth_keywords):
            # Check if it's in subdomain (very suspicious)
            if brand in domain.split('.')[0]:
                risk += 25
                reasons.append("HIGH: Authentication request from non-official domain")

        # MEDIUM-HIGH: Urgency + sensitive action
        urgency = {'urgent', 'immediate', 'expires', 'suspended', 'blocked', 'locked'}
        sensitive = {'verify', 'confirm', 'password', 'account', 'security'}
        if any(k in keywords for k in urgency) and any(k in keywords for k in sensitive):
            risk += 20
            reasons.append("HIGH: Urgency combined with sensitive action request")

        # Example: "login-paypal-secure.verifyinfo-auth.com"
        # - Contains brand: paypal (+20)
        # - Contains keywords: login, secure, verify, info, auth (+5+4+5+2+3 = 19)
        # - Multiple hyphens in subdomain (+6)
        # - Non-official domain (+10)
        # - Brand in subdomain with auth keyword (+25)
        # Total: 80+ (DEFINITELY PHISHING)

        return risk, reasons

    def _check_http_usage(self, parsed) -> Tuple[int, str]:
        """Check if URL uses HTTP instead of HTTPS"""
        risk = 0
        reason = None

        if parsed.scheme == 'http':
            # HTTP is suspicious, especially with sensitive keywords
            url_str = parsed.geturl().lower()

            # Critical if HTTP + sensitive keywords
            critical_keywords = ['login', 'signin', 'password', 'account', 'verify', 'bank', 'payment']
            if any(keyword in url_str for keyword in critical_keywords):
                risk = 15
                reason = "CRITICAL: Using insecure HTTP for sensitive operations (login/password/banking)"
            else:
                risk = 5
                reason = "Using insecure HTTP instead of HTTPS"

        return risk, reason

    def _check_suspicious_subdomains(self, domain: str, brand: str) -> Tuple[int, List[str]]:
        """Check for suspicious subdomain patterns"""
        risk = 0
        reasons = []

        if not domain:
            return risk, reasons

        parts = domain.split('.')
        if len(parts) <= 2:
            return risk, reasons  # No subdomains

        # Get all subdomains (everything except last 2 parts)
        subdomains = '.'.join(parts[:-2])

        # Check for suspicious keywords in subdomains
        suspicious_found = []
        for keyword in self.suspicious_subdomains:
            if keyword in subdomains:
                suspicious_found.append(keyword)

        if suspicious_found:
            # More suspicious if brand is also present
            if brand:
                risk += 15
                reasons.append(f"Suspicious subdomain '{suspicious_found[0]}' combined with brand name")
            else:
                risk += 8
                reasons.append(f"Suspicious subdomain pattern: {', '.join(suspicious_found[:2])}")

        # Check for excessive subdomains (more than 3 levels)
        if len(parts) > 4:
            risk += 10
            reasons.append(f"Excessive subdomain levels ({len(parts)-2}) - common in phishing")

        # Check for numeric subdomains
        if any(part.isdigit() for part in parts[:-2]):
            risk += 5
            reasons.append("Numeric subdomain detected - uncommon in legitimate sites")

        return risk, reasons

    def _check_url_shorteners(self, domain: str) -> Tuple[int, str]:
        """Check for URL shortening services"""
        shorteners = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'shorte.st'
        ]

        for shortener in shorteners:
            if shortener in domain:
                return 8, f"URL shortener detected ({shortener}) - hides actual destination"

        return 0, None

    def _check_suspicious_path(self, path: str, brand: str) -> Tuple[int, List[str]]:
        """Check for suspicious patterns in URL path"""
        risk = 0
        reasons = []

        if not path or path == '/':
            return risk, reasons

        path_lower = path.lower()

        # Check for suspicious file extensions
        suspicious_extensions = ['.exe', '.zip', '.rar', '.scr', '.bat', '.cmd', '.vbs', '.js']
        for ext in suspicious_extensions:
            if path_lower.endswith(ext):
                risk += 20
                reasons.append(f"CRITICAL: Executable file extension ({ext}) in URL - likely malware")
                break

        # Check for encoded characters (excessive URL encoding)
        encoded_count = path.count('%')
        if encoded_count > 3:
            risk += 10
            reasons.append(f"Excessive URL encoding ({encoded_count} encoded chars) - possible obfuscation")

        # Check for very long paths (> 100 chars)
        if len(path) > 100:
            risk += 8
            reasons.append(f"Unusually long URL path ({len(path)} chars) - possible obfuscation")

        # Check for sensitive keywords in path
        sensitive_path_keywords = ['login', 'signin', 'verify', 'confirm', 'update', 'secure']
        found_in_path = [kw for kw in sensitive_path_keywords if kw in path_lower]

        if found_in_path and brand:
            risk += 12
            reasons.append(f"Sensitive path '{found_in_path[0]}' with brand impersonation")
        elif found_in_path:
            risk += 5

        # Check for double extensions (file.pdf.exe)
        if path_lower.count('.') > 2:
            risk += 15
            reasons.append("Multiple file extensions detected - common malware technique")

        # Check for random-looking strings in path
        import re
        if re.search(r'[a-zA-Z0-9]{30,}', path):
            risk += 6
            reasons.append("Random character sequence in path - possibly generated phishing link")

        return risk, reasons

    def _get_verdict(self, risk_score: int) -> str:
        """Get human-readable verdict"""
        if risk_score >= 50:
            return "EXTREMELY_SUSPICIOUS"
        elif risk_score >= 30:
            return "HIGHLY_SUSPICIOUS"
        elif risk_score >= 15:
            return "SUSPICIOUS"
        elif risk_score >= 10:
            return "QUESTIONABLE"
        else:
            return "LOW_RISK"


if __name__ == '__main__':
    # Test with known phishing patterns
    detector = EnhancedPatternDetector()

    test_urls = [
        "http://login-paypal-secure.verifyinfo-auth.com/",
        "https://www.paypal.com/",
        "http://secure-login-amazon.tk/verify",
        "https://account-verify.microsoft-login.xyz/",
        "https://www.google.com/",
        "http://192.168.1.1/login",
        "https://urgent-verify-account.apple-security.ml/",
    ]

    print("=" * 70)
    print("Enhanced Pattern Detection Test")
    print("=" * 70)

    for url in test_urls:
        print(f"\nURL: {url}")
        result = detector.analyze_url(url)

        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Verdict: {result['verdict']}")
        print(f"Suspicious: {'YES' if result['is_suspicious'] else 'NO'}")

        if result['reasons']:
            print("Reasons:")
            for reason in result['reasons']:
                print(f"  - {reason}")
        print("-" * 70)
