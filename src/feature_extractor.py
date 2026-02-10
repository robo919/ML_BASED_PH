"""
Feature Extractor Module for ML Phishing URL Detection System
Comprehensive feature engineering for URL analysis
"""

import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse, parse_qs
import math
from typing import Dict, List
import logging
import yaml
from collections import Counter

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Comprehensive feature extraction for phishing URL detection
    Extracts lexical, structural, and advanced features
    """

    def __init__(self, config_path: str = 'config.yaml', patterns_path: str = 'data/phishing_patterns.yaml'):
        """Initialize feature extractor with configuration"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        self.suspicious_tlds = self.config['features']['suspicious_tlds']
        self.suspicious_keywords = self.config['features']['suspicious_keywords']
        self.brand_names = self.config['features']['brand_names']
        self.url_shorteners = self.config['features']['url_shorteners']

        # Load phishing patterns database
        try:
            with open(patterns_path, 'r') as f:
                self.phishing_patterns = yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Phishing patterns file not found at {patterns_path}, using config patterns only")
            self.phishing_patterns = None

    def extract_all_features(self, url: str) -> Dict:
        """
        Extract all features from a URL

        Args:
            url: URL string to analyze

        Returns:
            Dictionary of extracted features
        """
        features = {}

        try:
            # Parse URL
            parsed = urlparse(url)

            # Extract individual feature groups
            features.update(self.extract_lexical_features(url, parsed))
            features.update(self.extract_structural_features(url, parsed))
            features.update(self.extract_advanced_features(url, parsed))
            features.update(self.extract_statistical_features(url, parsed))

            # Check against phishing patterns database
            pattern_features = self._check_phishing_patterns(url, parsed.netloc, parsed.path)
            features.update(pattern_features)

            # Comprehensive brand impersonation detection
            brand_features = self._detect_brand_impersonation(parsed.netloc)
            features.update(brand_features)

        except Exception as e:
            logger.error(f"Error extracting features from URL {url}: {e}")
            # Return default features
            features = self._get_default_features()

        return features

    def extract_lexical_features(self, url: str, parsed) -> Dict:
        """Extract lexical features from URL"""
        features = {}

        # URL length features
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)

        # Character counts
        features['dot_count'] = url.count('.')
        features['slash_count'] = url.count('/')
        features['hyphen_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['question_mark_count'] = url.count('?')
        features['equal_count'] = url.count('=')
        features['at_count'] = url.count('@')
        features['ampersand_count'] = url.count('&')

        # Character ratios
        features['digit_count'] = sum(c.isdigit() for c in url)
        features['letter_count'] = sum(c.isalpha() for c in url)
        features['special_char_count'] = len(url) - features['digit_count'] - features['letter_count']

        features['digit_ratio'] = features['digit_count'] / len(url) if len(url) > 0 else 0
        features['letter_ratio'] = features['letter_count'] / len(url) if len(url) > 0 else 0
        features['special_char_ratio'] = features['special_char_count'] / len(url) if len(url) > 0 else 0

        # Entropy (randomness measure)
        features['url_entropy'] = self._calculate_entropy(url)
        features['domain_entropy'] = self._calculate_entropy(parsed.netloc)

        # Suspicious keyword count
        features['suspicious_keyword_count'] = sum(
            1 for keyword in self.suspicious_keywords
            if keyword.lower() in url.lower()
        )

        return features

    def extract_structural_features(self, url: str, parsed) -> Dict:
        """Extract structural features from URL"""
        features = {}

        # Protocol
        features['is_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_http'] = 1 if parsed.scheme in ['http', 'https'] else 0

        # IP address detection
        features['has_ip_address'] = self._has_ip_address(parsed.netloc)

        # @ symbol (often used in phishing)
        features['has_at_symbol'] = 1 if '@' in url else 0

        # Subdomain count
        domain_parts = parsed.netloc.split('.')
        features['subdomain_count'] = max(0, len(domain_parts) - 2)

        # URL depth (number of subdirectories)
        path_parts = [p for p in parsed.path.split('/') if p]
        features['url_depth'] = len(path_parts)

        # TLD features (with error handling)
        try:
            tld = self._extract_tld(parsed.netloc)
            features['tld_length'] = len(tld) if tld else 0
            # Check if TLD is suspicious (case-insensitive comparison)
            features['is_suspicious_tld'] = 1 if tld and any(tld.lower() == susp_tld.lower() for susp_tld in self.suspicious_tlds) else 0
        except Exception:
            features['tld_length'] = 0
            features['is_suspicious_tld'] = 0

        # Port number
        features['has_port'] = 1 if ':' in parsed.netloc and '@' not in parsed.netloc else 0

        # Query parameters
        query_params = parse_qs(parsed.query)
        features['query_param_count'] = len(query_params)

        # Fragment
        features['has_fragment'] = 1 if parsed.fragment else 0

        return features

    def extract_advanced_features(self, url: str, parsed) -> Dict:
        """Extract advanced features from URL"""
        features = {}

        # URL shortener detection
        features['is_url_shortener'] = self._is_url_shortener(parsed.netloc)

        # Abnormal patterns
        features['has_double_slash_in_path'] = 1 if '//' in parsed.path else 0
        features['has_double_dot'] = 1 if '..' in url else 0

        # Hexadecimal characters
        hex_pattern = r'%[0-9a-fA-F]{2}'
        features['hex_char_count'] = len(re.findall(hex_pattern, url))
        features['has_hex_encoding'] = 1 if features['hex_char_count'] > 0 else 0

        # Brand name detection
        features['brand_name_count'] = sum(
            1 for brand in self.brand_names
            if brand.lower() in parsed.netloc.lower()
        )

        # Brand + suspicious TLD combination (safely check if key exists)
        features['brand_with_suspicious_tld'] = 1 if (
            features.get('brand_name_count', 0) > 0 and features.get('is_suspicious_tld', 0) == 1
        ) else 0

        # Punycode detection and decoding
        features['has_punycode'] = 1 if 'xn--' in parsed.netloc else 0

        # Decode punycode if present and analyze
        decoded_domain = self._decode_punycode(parsed.netloc)
        features['punycode_length_diff'] = len(decoded_domain) - len(parsed.netloc)

        # IDN Homograph Attack Detection (enhanced)
        idn_score = self._detect_idn_homograph(decoded_domain)
        features['idn_homograph_score'] = idn_score
        # Higher threshold (0.5) to reduce false positives on legitimate sites
        features['is_idn_homograph'] = 1 if idn_score > 0.5 else 0

        # Check if punycode decodes to brand name
        features['punycode_brand_similarity'] = self._check_punycode_brand_similarity(parsed.netloc)

        # Unicode character detection (potential homograph)
        features['has_unicode_chars'] = 1 if any(ord(c) > 127 for c in parsed.netloc) else 0
        features['mixed_scripts'] = self._detect_mixed_scripts(parsed.netloc)

        # Multiple subdomains with hyphens (common phishing pattern)
        features['has_hyphen_in_domain'] = 1 if '-' in parsed.netloc else 0
        features['hyphen_domain_ratio'] = (
            parsed.netloc.count('-') / len(parsed.netloc) if len(parsed.netloc) > 0 else 0
        )

        # Check for common file extensions
        suspicious_extensions = ['.exe', '.zip', '.apk', '.scr', '.bat', '.cmd']
        features['has_suspicious_extension'] = 1 if any(
            url.lower().endswith(ext) for ext in suspicious_extensions
        ) else 0

        return features

    def extract_statistical_features(self, url: str, parsed) -> Dict:
        """Extract statistical features from URL"""
        features = {}

        # Vowel/consonant ratio in domain
        domain = parsed.netloc.lower()
        vowels = sum(1 for c in domain if c in 'aeiou')
        consonants = sum(1 for c in domain if c.isalpha() and c not in 'aeiou')

        features['vowel_count'] = vowels
        features['consonant_count'] = consonants
        features['vowel_consonant_ratio'] = (
            vowels / consonants if consonants > 0 else 0
        )

        # Longest word length in URL
        words = re.findall(r'[a-zA-Z]+', url)
        features['longest_word_length'] = max((len(w) for w in words), default=0)
        features['average_word_length'] = (
            sum(len(w) for w in words) / len(words) if words else 0
        )

        # Token count (words/numbers separated by special chars)
        tokens = re.findall(r'\w+', url)
        features['token_count'] = len(tokens)

        # Digit sequences
        digit_sequences = re.findall(r'\d+', url)
        features['digit_sequence_count'] = len(digit_sequences)
        features['max_digit_sequence_length'] = max(
            (len(seq) for seq in digit_sequences), default=0
        )

        # Consecutive character patterns
        features['max_consecutive_consonants'] = self._max_consecutive_chars(
            domain, 'bcdfghjklmnpqrstvwxyz'
        )
        features['max_consecutive_digits'] = self._max_consecutive_chars(
            url, '0123456789'
        )

        return features

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0

        # Count character frequencies
        counter = Counter(text)
        length = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    def _has_ip_address(self, domain: str) -> int:
        """Check if domain contains an IP address"""
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'

        # IPv6 pattern (simplified)
        ipv6_pattern = r'^[0-9a-fA-F:]+$'

        # Remove port if present
        domain_clean = domain.split(':')[0]

        if re.match(ipv4_pattern, domain_clean):
            return 1
        if re.match(ipv6_pattern, domain_clean) and ':' in domain_clean:
            return 1

        return 0

    def _extract_tld(self, domain: str) -> str:
        """Extract top-level domain from domain string"""
        if not domain:
            return ''

        # Remove port if present
        domain = domain.split(':')[0]

        # Remove any trailing/leading dots
        domain = domain.strip('.')

        parts = domain.split('.')
        if len(parts) >= 1:
            # Return just the last part as TLD (e.g., 'com', 'org', 'icu')
            tld = '.' + parts[-1]
            return tld
        return ''

    def _is_url_shortener(self, domain: str) -> int:
        """Check if domain is a known URL shortener"""
        return 1 if any(shortener in domain for shortener in self.url_shorteners) else 0

    def _max_consecutive_chars(self, text: str, char_set: str) -> int:
        """Find maximum consecutive characters from a character set"""
        max_count = 0
        current_count = 0

        for char in text.lower():
            if char in char_set:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0

        return max_count

    def _get_comprehensive_confusables(self) -> dict:
        """
        Comprehensive Unicode confusables database for IDN homograph detection
        Based on Unicode Security Considerations and common phishing patterns
        """
        return {
            # Cyrillic to Latin confusables
            '\u0430': 'a',   # CYRILLIC SMALL LETTER A
            '\u0435': 'e',   # CYRILLIC SMALL LETTER IE
            '\u043e': 'o',   # CYRILLIC SMALL LETTER O
            '\u0440': 'p',   # CYRILLIC SMALL LETTER ER
            '\u0441': 'c',   # CYRILLIC SMALL LETTER ES
            '\u0445': 'x',   # CYRILLIC SMALL LETTER HA
            '\u0443': 'y',   # CYRILLIC SMALL LETTER U
            '\u0456': 'i',   # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
            '\u0458': 'j',   # CYRILLIC SMALL LETTER JE
            '\u0455': 's',   # CYRILLIC SMALL LETTER DZE
            '\u0501': 'd',   # CYRILLIC SMALL LETTER KOMI DE
            '\u04bb': 'h',   # CYRILLIC SMALL LETTER SHHA
            '\u0461': 'w',   # CYRILLIC SMALL LETTER OMEGA
            '\u0475': 'v',   # CYRILLIC SMALL LETTER IZHITSA

            # Cyrillic capitals
            '\u0410': 'A',   # CYRILLIC CAPITAL LETTER A
            '\u0412': 'B',   # CYRILLIC CAPITAL LETTER VE
            '\u0415': 'E',   # CYRILLIC CAPITAL LETTER IE
            '\u041a': 'K',   # CYRILLIC CAPITAL LETTER KA
            '\u041c': 'M',   # CYRILLIC CAPITAL LETTER EM
            '\u041d': 'H',   # CYRILLIC CAPITAL LETTER EN
            '\u041e': 'O',   # CYRILLIC CAPITAL LETTER O
            '\u0420': 'P',   # CYRILLIC CAPITAL LETTER ER
            '\u0421': 'C',   # CYRILLIC CAPITAL LETTER ES
            '\u0422': 'T',   # CYRILLIC CAPITAL LETTER TE
            '\u0425': 'X',   # CYRILLIC CAPITAL LETTER HA
            '\u0405': 'S',   # CYRILLIC CAPITAL LETTER DZE

            # Greek to Latin confusables
            '\u03b1': 'a',   # GREEK SMALL LETTER ALPHA
            '\u03b5': 'e',   # GREEK SMALL LETTER EPSILON
            '\u03b9': 'i',   # GREEK SMALL LETTER IOTA
            '\u03bf': 'o',   # GREEK SMALL LETTER OMICRON
            '\u03c1': 'p',   # GREEK SMALL LETTER RHO
            '\u03c5': 'y',   # GREEK SMALL LETTER UPSILON
            '\u03c7': 'x',   # GREEK SMALL LETTER CHI
            '\u03bd': 'v',   # GREEK SMALL LETTER NU
            '\u03c4': 't',   # GREEK SMALL LETTER TAU

            # Greek capitals
            '\u0391': 'A',   # GREEK CAPITAL LETTER ALPHA
            '\u0392': 'B',   # GREEK CAPITAL LETTER BETA
            '\u0395': 'E',   # GREEK CAPITAL LETTER EPSILON
            '\u0396': 'Z',   # GREEK CAPITAL LETTER ZETA
            '\u0397': 'H',   # GREEK CAPITAL LETTER ETA
            '\u0399': 'I',   # GREEK CAPITAL LETTER IOTA
            '\u039a': 'K',   # GREEK CAPITAL LETTER KAPPA
            '\u039c': 'M',   # GREEK CAPITAL LETTER MU
            '\u039d': 'N',   # GREEK CAPITAL LETTER NU
            '\u039f': 'O',   # GREEK CAPITAL LETTER OMICRON
            '\u03a1': 'P',   # GREEK CAPITAL LETTER RHO
            '\u03a4': 'T',   # GREEK CAPITAL LETTER TAU
            '\u03a5': 'Y',   # GREEK CAPITAL LETTER UPSILON
            '\u03a7': 'X',   # GREEK CAPITAL LETTER CHI
            '\u0396': 'Z',   # GREEK CAPITAL LETTER ZETA

            # Special Latin variations
            '\u0131': 'i',   # LATIN SMALL LETTER DOTLESS I
            '\u017f': 's',   # LATIN SMALL LETTER LONG S
            '\u0138': 'k',   # LATIN SMALL LETTER KRA
            '\u0140': 'l',   # LATIN SMALL LETTER L WITH MIDDLE DOT

            # Armenian confusables
            '\u0578': 'o',   # ARMENIAN SMALL LETTER VO
            '\u0585': 'o',   # ARMENIAN SMALL LETTER OH

            # Hebrew confusables
            '\u05d5': 'i',   # HEBREW LETTER VAV
            '\u05c1': 'i',   # HEBREW POINT SHIN DOT

            # Numeric and symbol confusables
            '\u0030': '0',   # DIGIT ZERO (can confuse with O)
            '\u004f': 'O',   # LATIN CAPITAL LETTER O
            '\u006f': 'o',   # LATIN SMALL LETTER O
            '\u0031': '1',   # DIGIT ONE (can confuse with l/I)
            '\u006c': 'l',   # LATIN SMALL LETTER L
            '\u0049': 'I',   # LATIN CAPITAL LETTER I
            '\u0033': '3',   # DIGIT THREE (can confuse with E)
            '\u0035': '5',   # DIGIT FIVE (can confuse with S)
            '\u0036': '6',   # DIGIT SIX (can confuse with b)
            '\u0038': '8',   # DIGIT EIGHT (can confuse with B)

            # Mathematical alphanumerics (often abused)
            '\U0001d400': 'A',  # MATHEMATICAL BOLD CAPITAL A
            '\U0001d41a': 'a',  # MATHEMATICAL BOLD SMALL A
        }

    def _detect_idn_homograph(self, domain: str) -> float:
        """
        Enhanced IDN homograph attack detection
        Returns a score from 0 (safe) to 1 (very suspicious)

        Detects:
        - Unicode confusable characters
        - Mixed character sets
        - Punycode encoding
        - Visual similarity to known brands
        """
        confusables = self._get_comprehensive_confusables()

        score = 0.0
        confusable_count = 0
        total_chars = len(domain)

        # Check for confusable characters
        for char in domain:
            if char in confusables:
                confusable_count += 1

        if confusable_count > 0:
            # Score based on percentage of confusable characters
            confusable_ratio = confusable_count / total_chars if total_chars > 0 else 0
            score += min(confusable_ratio * 2.0, 0.8)

        # Check for mixed character sets (very strong indicator)
        if self._has_mixed_character_sets(domain):
            score += 0.6

        # Check for punycode (xn--)
        if 'xn--' in domain.lower():
            score += 0.4

        # Check for homograph similarity to popular domains
        similarity_score = self._check_homograph_similarity(domain)
        score += similarity_score * 0.3

        return min(score, 1.0)

    def _check_homograph_similarity(self, domain: str) -> float:
        """
        Check if domain is visually similar to popular brands using confusables
        """
        confusables = self._get_comprehensive_confusables()

        # Normalize domain by replacing confusables
        normalized = ''
        for char in domain.lower():
            normalized += confusables.get(char, char)

        # Popular brands to check against
        popular_brands = [
            'paypal', 'google', 'microsoft', 'apple', 'amazon',
            'facebook', 'netflix', 'instagram', 'twitter', 'linkedin',
            'ebay', 'yahoo', 'bankofamerica', 'wellsfargo', 'chase'
        ]

        # Check for exact or near matches
        for brand in popular_brands:
            if brand in normalized:
                # If normalized contains brand but original didn't, it's suspicious
                if brand not in domain.lower():
                    return 1.0
                # Check for close variations
                import difflib
                similarity = difflib.SequenceMatcher(None, brand, normalized).ratio()
                if similarity > 0.8:
                    return similarity

        return 0.0

    def _has_mixed_character_sets(self, text: str) -> bool:
        """Check if text contains mixed character sets (Latin + Cyrillic/Greek)"""
        has_latin = False
        has_cyrillic = False
        has_greek = False

        for char in text:
            if '\u0041' <= char <= '\u007A':  # Latin
                has_latin = True
            elif '\u0400' <= char <= '\u04FF':  # Cyrillic
                has_cyrillic = True
            elif '\u0370' <= char <= '\u03FF':  # Greek
                has_greek = True

        # Mixed scripts are suspicious
        return has_latin and (has_cyrillic or has_greek)

    def _detect_mixed_scripts(self, domain: str) -> int:
        """Detect if domain uses mixed scripts (0=no, 1=yes)"""
        return 1 if self._has_mixed_character_sets(domain) else 0

    def _decode_punycode(self, domain: str) -> str:
        """
        Decode punycode domain to Unicode representation
        Punycode domains start with 'xn--'
        """
        try:
            # Split domain into parts
            parts = domain.split('.')

            # Decode each part if it's punycode
            decoded_parts = []
            for part in parts:
                if part.startswith('xn--'):
                    try:
                        # Remove 'xn--' prefix and decode
                        decoded = part.encode('ascii').decode('idna')
                        decoded_parts.append(decoded)
                    except Exception:
                        decoded_parts.append(part)
                else:
                    decoded_parts.append(part)

            return '.'.join(decoded_parts)

        except Exception:
            return domain

    def _check_punycode_brand_similarity(self, domain: str) -> float:
        """
        Check if punycode domain decodes to something similar to a brand
        Returns similarity score 0-1
        """
        if 'xn--' not in domain:
            return 0.0

        decoded = self._decode_punycode(domain)

        # If decoding changed the domain, analyze it
        if decoded != domain:
            # Check similarity to brands
            popular_brands = [
                'paypal', 'google', 'microsoft', 'apple', 'amazon',
                'facebook', 'netflix', 'instagram', 'twitter', 'linkedin',
                'ebay', 'yahoo', 'wellsfargo', 'chase', 'bankofamerica'
            ]

            import difflib
            max_similarity = 0.0

            for brand in popular_brands:
                similarity = difflib.SequenceMatcher(
                    None,
                    brand.lower(),
                    decoded.lower()
                ).ratio()

                if similarity > max_similarity:
                    max_similarity = similarity

            # If similarity is high, it's suspicious
            if max_similarity > 0.7:
                return max_similarity

        return 0.0

    def _detect_brand_impersonation(self, domain: str) -> Dict:
        """
        Comprehensive brand impersonation detection
        Returns dict with impersonation indicators
        """
        domain_lower = domain.lower()

        results = {
            'brand_impersonation_score': 0.0,
            'likely_brand_impersonation': 0,
            'brand_in_subdomain': 0,
            'brand_with_hyphens': 0
        }

        # Define major brands to protect
        major_brands = [
            'paypal', 'google', 'microsoft', 'apple', 'amazon',
            'facebook', 'netflix', 'instagram', 'twitter', 'linkedin',
            'dropbox', 'adobe', 'ebay', 'yahoo', 'wells', 'chase',
            'bankofamerica', 'citibank', 'usbank'
        ]

        score = 0.0

        for brand in major_brands:
            if brand in domain_lower:
                # Check if brand is in legitimate domain
                legitimate_domains = {
                    'paypal': ['paypal.com', 'paypal.co.uk'],
                    'google': ['google.com', 'gmail.com', 'youtube.com', 'gstatic.com', 'googleapis.com'],
                    'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'msn.com', 'office.com'],
                    'apple': ['apple.com', 'icloud.com', 'me.com'],
                    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazonaws.com'],
                    'facebook': ['facebook.com', 'fb.com', 'fbcdn.net'],
                    'netflix': ['netflix.com', 'nflxvideo.net'],
                    'instagram': ['instagram.com', 'cdninstagram.com'],
                    'twitter': ['twitter.com', 't.co', 'twimg.com'],
                    'linkedin': ['linkedin.com', 'licdn.com'],
                    'dropbox': ['dropbox.com', 'dropboxusercontent.com'],
                    'adobe': ['adobe.com', 'adobecc.com'],
                    'ebay': ['ebay.com', 'ebayimg.com'],
                    'yahoo': ['yahoo.com', 'yimg.com'],
                    'wells': ['wellsfargo.com'],
                    'chase': ['chase.com'],
                    'bankofamerica': ['bankofamerica.com'],
                    'citibank': ['citibank.com', 'citi.com'],
                    'usbank': ['usbank.com']
                }

                # Check if this is a legitimate domain
                is_legitimate = False
                if brand in legitimate_domains:
                    for legit_domain in legitimate_domains[brand]:
                        if domain_lower.endswith(legit_domain) or domain_lower == legit_domain:
                            is_legitimate = True
                            break

                if not is_legitimate:
                    # Brand found but not in legitimate domain - likely impersonation
                    score += 0.5
                    results['likely_brand_impersonation'] = 1

                    # Check if brand is in subdomain (e.g., paypal.phishing.com)
                    domain_parts = domain_lower.split('.')
                    if len(domain_parts) > 2 and brand in '.'.join(domain_parts[:-2]):
                        score += 0.3
                        results['brand_in_subdomain'] = 1

                    # Check if brand has hyphens around it (e.g., pay-pal.com, paypal-secure.com)
                    if f'-{brand}' in domain_lower or f'{brand}-' in domain_lower:
                        score += 0.2
                        results['brand_with_hyphens'] = 1

        results['brand_impersonation_score'] = min(score, 1.0)

        return results

    def _check_phishing_patterns(self, url: str, domain: str, path: str) -> Dict:
        """
        Check URL against known phishing patterns from database
        Returns dict with pattern match scores
        """
        if not self.phishing_patterns:
            return {
                'phishing_keyword_match': 0,
                'suspicious_pattern_match': 0,
                'typosquatting_detected': 0,
                'suspicious_port': 0,
                'suspicious_extension': 0,
                'known_phishing_path': 0
            }

        url_lower = url.lower()
        domain_lower = domain.lower()
        path_lower = path.lower()

        results = {
            'phishing_keyword_match': 0,
            'suspicious_pattern_match': 0,
            'typosquatting_detected': 0,
            'suspicious_port': 0,
            'suspicious_extension': 0,
            'known_phishing_path': 0
        }

        # Check phishing keywords
        phishing_keywords = self.phishing_patterns.get('phishing_keywords', [])
        for keyword in phishing_keywords:
            if keyword in url_lower:
                results['phishing_keyword_match'] = 1
                break

        # Check suspicious patterns (regex)
        suspicious_patterns = self.phishing_patterns.get('suspicious_patterns', [])
        for pattern in suspicious_patterns:
            try:
                if re.search(pattern, url_lower):
                    results['suspicious_pattern_match'] = 1
                    break
            except re.error:
                continue

        # Check typosquatting
        typosquatting = self.phishing_patterns.get('typosquatting_patterns', {})
        for brand, variants in typosquatting.items():
            for variant in variants:
                if variant in domain_lower:
                    results['typosquatting_detected'] = 1
                    break
            if results['typosquatting_detected']:
                break

        # Check suspicious ports
        suspicious_ports = self.phishing_patterns.get('suspicious_ports', [])
        for port in suspicious_ports:
            if f':{port}' in url_lower:
                results['suspicious_port'] = 1
                break

        # Check suspicious extensions
        suspicious_extensions = self.phishing_patterns.get('suspicious_extensions', [])
        for ext in suspicious_extensions:
            if url_lower.endswith(ext):
                results['suspicious_extension'] = 1
                break

        # Check known phishing paths
        phishing_paths = self.phishing_patterns.get('phishing_paths', [])
        for phish_path in phishing_paths:
            if phish_path in path_lower:
                results['known_phishing_path'] = 1
                break

        return results

    def _get_default_features(self) -> Dict:
        """Return default feature values in case of extraction error"""
        default_features = {
            'url_length': 0,
            'domain_length': 0,
            'path_length': 0,
            'query_length': 0,
            'dot_count': 0,
            'slash_count': 0,
            'hyphen_count': 0,
            'underscore_count': 0,
            'question_mark_count': 0,
            'equal_count': 0,
            'at_count': 0,
            'ampersand_count': 0,
            'digit_count': 0,
            'letter_count': 0,
            'special_char_count': 0,
            'digit_ratio': 0.0,
            'letter_ratio': 0.0,
            'special_char_ratio': 0.0,
            'url_entropy': 0.0,
            'domain_entropy': 0.0,
            'suspicious_keyword_count': 0,
            'is_https': 0,
            'has_http': 0,
            'has_ip_address': 0,
            'has_at_symbol': 0,
            'subdomain_count': 0,
            'url_depth': 0,
            'tld_length': 0,
            'is_suspicious_tld': 0,
            'has_port': 0,
            'query_param_count': 0,
            'has_fragment': 0,
            'is_url_shortener': 0,
            'has_double_slash_in_path': 0,
            'has_double_dot': 0,
            'hex_char_count': 0,
            'has_hex_encoding': 0,
            'brand_name_count': 0,
            'brand_with_suspicious_tld': 0,
            'has_punycode': 0,
            'punycode_length_diff': 0,
            'punycode_brand_similarity': 0.0,
            'idn_homograph_score': 0.0,
            'is_idn_homograph': 0,
            'has_unicode_chars': 0,
            'mixed_scripts': 0,
            'phishing_keyword_match': 0,
            'suspicious_pattern_match': 0,
            'typosquatting_detected': 0,
            'suspicious_port': 0,
            'suspicious_extension': 0,
            'known_phishing_path': 0,
            'brand_impersonation_score': 0.0,
            'likely_brand_impersonation': 0,
            'brand_in_subdomain': 0,
            'brand_with_hyphens': 0,
            'has_hyphen_in_domain': 0,
            'hyphen_domain_ratio': 0.0,
            'has_suspicious_extension': 0,
            'vowel_count': 0,
            'consonant_count': 0,
            'vowel_consonant_ratio': 0.0,
            'longest_word_length': 0,
            'average_word_length': 0.0,
            'token_count': 0,
            'digit_sequence_count': 0,
            'max_digit_sequence_length': 0,
            'max_consecutive_consonants': 0,
            'max_consecutive_digits': 0
        }
        return default_features

    def extract_features_from_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from a dataframe of URLs

        Args:
            df: DataFrame with 'url' column

        Returns:
            DataFrame with extracted features
        """
        logger.info(f"Extracting features from {len(df)} URLs...")

        # Extract features for each URL
        from tqdm import tqdm
        tqdm.pandas(desc="Extracting features")

        features_list = df['url'].progress_apply(self.extract_all_features)

        # Convert list of dicts to DataFrame
        features_df = pd.DataFrame(features_list.tolist())

        # Combine with original dataframe
        result_df = pd.concat([df, features_df], axis=1)

        logger.info(f"Feature extraction complete. Total features: {len(features_df.columns)}")

        return result_df

    def get_feature_names(self) -> List[str]:
        """Get list of all feature names"""
        return list(self._get_default_features().keys())


if __name__ == '__main__':
    # Test feature extraction
    extractor = FeatureExtractor()

    test_urls = [
        'https://www.google.com',
        'http://secure-paypal-login.ml/verify',
        'https://192.168.1.1/admin',
        'http://bit.ly/abc123'
    ]

    for url in test_urls:
        print(f"\nURL: {url}")
        features = extractor.extract_all_features(url)
        print(f"Extracted {len(features)} features")
        for k, v in list(features.items())[:10]:
            print(f"  {k}: {v}")
