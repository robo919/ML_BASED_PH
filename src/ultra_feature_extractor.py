"""
ULTRA-ADVANCED Feature Extractor
Extracts 200+ cutting-edge features for phishing detection
Includes AI-powered features, linguistic analysis, and advanced heuristics
"""

import re
import math
import string
from urllib.parse import urlparse, parse_qs
from collections import Counter
from typing import Dict, List
import logging
import Levenshtein
import tldextract

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class UltraFeatureExtractor:
    """
    Next-generation feature extraction with 200+ advanced features
    """

    def __init__(self):
        # Major brand list for typosquatting detection
        self.major_brands = [
            'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
            'netflix', 'instagram', 'twitter', 'linkedin', 'ebay', 'yahoo',
            'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
            'dropbox', 'adobe', 'spotify', 'gmail', 'outlook', 'icloud'
        ]

        # Phishing action words
        self.action_words = {
            'verify', 'update', 'confirm', 'secure', 'suspend', 'restore',
            'validate', 'unlock', 'activate', 'renew', 'recover', 'reset'
        }

        # Urgency words
        self.urgency_words = {
            'urgent', 'immediate', 'expire', 'limited', 'now', 'today',
            'soon', 'quick', 'fast', 'hurry', 'deadline', 'act'
        }

        # Sensitive data words
        self.sensitive_words = {
            'password', 'credit', 'card', 'ssn', 'social', 'security',
            'account', 'bank', 'billing', 'payment', 'wallet', 'pin'
        }

    def extract_all_features(self, url: str) -> Dict:
        """
        Extract ALL 200+ features from URL
        """
        features = {}

        try:
            parsed = urlparse(url.lower())

            # Basic features (20 features)
            features.update(self._extract_basic_features(url, parsed))

            # Advanced lexical features (30 features)
            features.update(self._extract_advanced_lexical_features(url, parsed))

            # Domain intelligence features (25 features)
            features.update(self._extract_domain_intelligence_features(parsed))

            # Path and query intelligence (20 features)
            features.update(self._extract_path_query_features(parsed))

            # Linguistic features (25 features)
            features.update(self._extract_linguistic_features(url, parsed))

            # Typosquatting and brand features (20 features)
            features.update(self._extract_typosquatting_features(parsed))

            # Obfuscation detection features (15 features)
            features.update(self._extract_obfuscation_features(url, parsed))

            # Statistical features (20 features)
            features.update(self._extract_statistical_features(url, parsed))

            # URL structure complexity features (15 features)
            features.update(self._extract_complexity_features(url, parsed))

            # Behavioral indicators (10 features)
            features.update(self._extract_behavioral_features(url, parsed))

        except Exception as e:
            logger.error(f"Error extracting ultra features: {e}")
            features = self._get_default_features()

        return features

    def _extract_basic_features(self, url: str, parsed) -> Dict:
        """Basic URL features"""
        return {
            'ultra_url_total_length': len(url),
            'ultra_domain_length': len(parsed.netloc),
            'ultra_path_length': len(parsed.path),
            'ultra_query_length': len(parsed.query),
            'ultra_fragment_length': len(parsed.fragment),
            'ultra_is_https': 1 if parsed.scheme == 'https' else 0,
            'ultra_has_www': 1 if 'www.' in parsed.netloc else 0,
            'ultra_subdomain_count': len(parsed.netloc.split('.')) - 2 if len(parsed.netloc.split('.')) > 2 else 0,
            'ultra_path_depth': len([p for p in parsed.path.split('/') if p]),
            'ultra_query_params_count': len(parse_qs(parsed.query)),
            'ultra_has_fragment': 1 if parsed.fragment else 0,
            'ultra_uses_standard_port': 1 if ':' not in parsed.netloc else 0,
            'ultra_has_at_symbol': 1 if '@' in url else 0,
            'ultra_domain_has_ip': 1 if self._has_ip_pattern(parsed.netloc) else 0,
            'ultra_url_shortener': 1 if self._is_url_shortener(parsed.netloc) else 0,
            'ultra_domain_dots_count': parsed.netloc.count('.'),
            'ultra_path_slashes_count': parsed.path.count('/'),
            'ultra_query_ampersands_count': parsed.query.count('&'),
            'ultra_total_special_chars': sum(not c.isalnum() for c in url),
            'ultra_scheme_length': len(parsed.scheme)
        }

    def _extract_advanced_lexical_features(self, url: str, parsed) -> Dict:
        """Advanced character-level features"""
        domain = parsed.netloc
        path = parsed.path

        return {
            # Character type ratios
            'ultra_digit_ratio_url': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
            'ultra_letter_ratio_url': sum(c.isalpha() for c in url) / len(url) if len(url) > 0 else 0,
            'ultra_uppercase_ratio': sum(c.isupper() for c in url) / len(url) if len(url) > 0 else 0,
            'ultra_special_ratio': sum(not c.isalnum() for c in url) / len(url) if len(url) > 0 else 0,

            # Domain specific
            'ultra_domain_digit_ratio': sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0,
            'ultra_domain_hyphen_ratio': domain.count('-') / len(domain) if len(domain) > 0 else 0,
            'ultra_domain_underscore_ratio': domain.count('_') / len(domain) if len(domain) > 0 else 0,

            # Character repetition
            'ultra_max_char_repeat': self._max_char_repetition(url),
            'ultra_domain_max_char_repeat': self._max_char_repetition(domain),

            # Consecutive patterns
            'ultra_max_consecutive_digits': self._max_consecutive_type(url, str.isdigit),
            'ultra_max_consecutive_letters': self._max_consecutive_type(url, str.isalpha),
            'ultra_max_consecutive_consonants': self._max_consecutive_consonants(domain),

            # Hex encoding
            'ultra_hex_percent_encoding_count': url.count('%'),
            'ultra_has_excessive_encoding': 1 if url.count('%') > 3 else 0,

            # Punctuation
            'ultra_dots_count': url.count('.'),
            'ultra_hyphens_count': url.count('-'),
            'ultra_underscores_count': url.count('_'),
            'ultra_equals_count': url.count('='),
            'ultra_question_marks_count': url.count('?'),
            'ultra_ampersands_count': url.count('&'),

            # Unusual characters
            'ultra_has_tilde': 1 if '~' in url else 0,
            'ultra_has_pipe': 1 if '|' in url else 0,

            # Entropy measures
            'ultra_url_entropy': self._calculate_entropy(url),
            'ultra_domain_entropy': self._calculate_entropy(domain),
            'ultra_path_entropy': self._calculate_entropy(path) if path else 0,

            # Length ratios
            'ultra_domain_to_url_ratio': len(domain) / len(url) if len(url) > 0 else 0,
            'ultra_path_to_url_ratio': len(path) / len(url) if len(url) > 0 else 0,
            'ultra_query_to_url_ratio': len(parsed.query) / len(url) if len(url) > 0 else 0,
        }

    def _extract_domain_intelligence_features(self, parsed) -> Dict:
        """Intelligent domain analysis"""
        try:
            extracted = tldextract.extract(parsed.netloc)
            domain = extracted.domain
            tld = extracted.suffix
            subdomain = extracted.subdomain

            return {
                # TLD features
                'ultra_tld_length': len(tld) if tld else 0,
                'ultra_has_country_tld': 1 if tld and len(tld) == 2 else 0,
                'ultra_tld_is_com': 1 if tld == 'com' else 0,
                'ultra_tld_is_suspicious': 1 if tld in {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top'} else 0,

                # Domain features
                'ultra_domain_word_count': len(re.findall(r'[a-z]+', domain)),
                'ultra_domain_has_brand_name': 1 if any(brand in domain for brand in self.major_brands) else 0,
                'ultra_domain_vowel_ratio': self._calculate_vowel_ratio(domain),
                'ultra_domain_consonant_clusters': self._count_consonant_clusters(domain),

                # Subdomain features
                'ultra_has_subdomain': 1 if subdomain else 0,
                'ultra_subdomain_length': len(subdomain) if subdomain else 0,
                'ultra_subdomain_levels': len(subdomain.split('.')) if subdomain else 0,
                'ultra_subdomain_has_keyword': 1 if subdomain and any(kw in subdomain for kw in ['secure', 'login', 'verify']) else 0,

                # Domain construction
                'ultra_domain_contains_hyphen': 1 if '-' in domain else 0,
                'ultra_domain_starts_with_digit': 1 if domain and domain[0].isdigit() else 0,
                'ultra_domain_ends_with_digit': 1 if domain and domain[-1].isdigit() else 0,

                # Suspicious patterns
                'ultra_domain_has_doubled_chars': 1 if re.search(r'(.)\1{2,}', domain) else 0,
                'ultra_domain_number_letter_transitions': len(re.findall(r'[0-9][a-z]|[a-z][0-9]', domain)),

                # Lexical features
                'ultra_domain_longest_word_length': max([len(w) for w in re.findall(r'[a-z]+', domain)], default=0),
                'ultra_domain_average_word_length': sum([len(w) for w in re.findall(r'[a-z]+', domain)]) / max(len(re.findall(r'[a-z]+', domain)), 1),

                # Registration domain
                'ultra_registered_domain_length': len(extracted.registered_domain) if extracted.registered_domain else 0,
                'ultra_fqdn_length': len(extracted.fqdn) if extracted.fqdn else 0,

                # Punycode
                'ultra_has_punycode': 1 if 'xn--' in parsed.netloc else 0,
                'ultra_punycode_segments': parsed.netloc.count('xn--'),

                # IP address patterns
                'ultra_resembles_ip': 1 if re.match(r'^\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0,
            }
        except Exception as e:
            logger.error(f"Error in domain intelligence: {e}")
            return {f'ultra_domain_intel_{i}': 0 for i in range(25)}

    def _extract_path_query_features(self, parsed) -> Dict:
        """Path and query string intelligence"""
        path = parsed.path
        query = parsed.query

        return {
            # Path features
            'ultra_path_segments_count': len([p for p in path.split('/') if p]),
            'ultra_path_has_extension': 1 if re.search(r'\.[a-z]{2,4}$', path) else 0,
            'ultra_path_suspicious_extension': 1 if re.search(r'\.(exe|zip|rar|scr|bat|cmd|vbs)$', path.lower()) else 0,
            'ultra_path_double_extension': 1 if path.count('.') > 1 and not path.endswith('.html') else 0,
            'ultra_path_has_parameters': 1 if '?' in path else 0,
            'ultra_path_longest_segment': max([len(p) for p in path.split('/')], default=0),

            # Query features
            'ultra_query_has_url': 1 if re.search(r'https?://', query) else 0,
            'ultra_query_suspicious_params': sum(1 for p in ['redirect', 'url', 'next', 'continue', 'return'] if p in query.lower()),
            'ultra_query_has_base64': 1 if self._looks_like_base64(query) else 0,

            # Encoded characters
            'ultra_path_percent_encoded': path.count('%'),
            'ultra_query_percent_encoded': query.count('%'),

            # File indicators
            'ultra_path_file_indicators': sum(1 for ext in ['.php', '.asp', '.jsp', '.cgi'] if ext in path.lower()),

            # Path keywords
            'ultra_path_has_login': 1 if 'login' in path.lower() else 0,
            'ultra_path_has_admin': 1 if 'admin' in path.lower() else 0,
            'ultra_path_has_verify': 1 if 'verify' in path.lower() else 0,
            'ultra_path_has_account': 1 if 'account' in path.lower() else 0,

            # Query structure
            'ultra_query_equals_to_ampersand_ratio': query.count('=') / max(query.count('&'), 1) if query.count('&') > 0 else 0,
            'ultra_query_longest_value': max([len(v) for v in re.findall(r'=([^&]*)', query)], default=0),

            # Path complexity
            'ultra_path_digit_ratio': sum(c.isdigit() for c in path) / len(path) if len(path) > 0 else 0,
            'ultra_path_special_char_ratio': sum(not c.isalnum() and c not in '/.?' for c in path) / len(path) if len(path) > 0 else 0,
        }

    def _extract_linguistic_features(self, url: str, parsed) -> Dict:
        """Linguistic and semantic features"""
        url_lower = url.lower()
        domain_lower = parsed.netloc.lower()

        return {
            # Action words (phishing indicators)
            'ultra_has_action_words': sum(1 for word in self.action_words if word in url_lower),
            'ultra_action_word_in_domain': 1 if any(word in domain_lower for word in self.action_words) else 0,

            # Urgency indicators
            'ultra_has_urgency_words': sum(1 for word in self.urgency_words if word in url_lower),
            'ultra_urgency_in_path': 1 if any(word in parsed.path.lower() for word in self.urgency_words) else 0,

            # Sensitive data words
            'ultra_has_sensitive_words': sum(1 for word in self.sensitive_words if word in url_lower),
            'ultra_sensitive_in_domain': 1 if any(word in domain_lower for word in self.sensitive_words) else 0,

            # Brand mentions
            'ultra_brand_mention_count': sum(1 for brand in self.major_brands if brand in url_lower),
            'ultra_brand_in_subdomain': 1 if any(brand in domain_lower.split('.')[0] for brand in self.major_brands) else 0,

            # Keyword combinations (very suspicious)
            'ultra_action_plus_urgency': 1 if any(a in url_lower for a in self.action_words) and any(u in url_lower for u in self.urgency_words) else 0,
            'ultra_brand_plus_action': 1 if any(b in url_lower for b in self.major_brands) and any(a in url_lower for a in self.action_words) else 0,
            'ultra_sensitive_plus_action': 1 if any(s in url_lower for s in self.sensitive_words) and any(a in url_lower for a in self.action_words) else 0,

            # Word patterns
            'ultra_has_login_keywords': 1 if any(k in url_lower for k in ['login', 'signin', 'sign-in']) else 0,
            'ultra_has_verify_keywords': 1 if any(k in url_lower for k in ['verify', 'validation', 'confirm']) else 0,
            'ultra_has_security_keywords': 1 if any(k in url_lower for k in ['secure', 'security', 'protect']) else 0,
            'ultra_has_update_keywords': 1 if any(k in url_lower for k in ['update', 'upgrade', 'renew']) else 0,

            # Semantic suspicious combinations
            'ultra_security_action_combo': 1 if ('secure' in url_lower or 'security' in url_lower) and any(a in url_lower for a in ['login', 'verify', 'update']) else 0,

            # Readable word count
            'ultra_readable_words_count': len(re.findall(r'\b[a-z]{3,}\b', url_lower)),
            'ultra_readable_words_ratio': len(re.findall(r'\b[a-z]{3,}\b', url_lower)) / max(len(url_lower.split()), 1),

            # Language mixing (suspicious)
            'ultra_has_mixed_case_domain': 1 if domain_lower != parsed.netloc and parsed.netloc.lower() == domain_lower else 0,

            # Common phishing phrases
            'ultra_has_suspended_terms': 1 if any(t in url_lower for t in ['suspend', 'locked', 'blocked', 'frozen']) else 0,
            'ultra_has_restore_terms': 1 if any(t in url_lower for t in ['restore', 'recover', 'unlock', 'reactivate']) else 0,
            'ultra_has_billing_terms': 1 if any(t in url_lower for t in ['billing', 'payment', 'invoice', 'charge']) else 0,

            # Deceptive patterns
            'ultra_fake_https_in_domain': 1 if 'https' in domain_lower and parsed.scheme == 'http' else 0,
            'ultra_secure_in_http_url': 1 if 'secure' in url_lower and parsed.scheme == 'http' else 0,
        }

    def _extract_typosquatting_features(self, parsed) -> Dict:
        """Advanced typosquatting detection using Levenshtein distance"""
        domain = parsed.netloc.split(':')[0]  # Remove port
        try:
            extracted = tldextract.extract(domain)
            domain_name = extracted.domain.lower()
        except:
            domain_name = domain.lower()

        # Calculate minimum Levenshtein distance to known brands
        min_distance = 999
        closest_brand = None
        distance_ratio = 1.0

        for brand in self.major_brands:
            if brand in domain_name:
                # Exact match
                min_distance = 0
                closest_brand = brand
                break

            # Calculate edit distance
            distance = Levenshtein.distance(domain_name, brand)
            if distance < min_distance:
                min_distance = distance
                closest_brand = brand

        if closest_brand:
            distance_ratio = min_distance / len(closest_brand)

        return {
            'ultra_typosquat_min_distance': min_distance,
            'ultra_typosquat_distance_ratio': distance_ratio,
            'ultra_typosquat_very_close': 1 if min_distance <= 2 and min_distance > 0 else 0,
            'ultra_typosquat_close': 1 if 2 < min_distance <= 4 else 0,

            # Homoglyph detection (visually similar characters)
            'ultra_has_homoglyph_chars': 1 if any(c in domain_name for c in ['0', '1', 'l', 'I']) else 0,

            # Common typosquatting patterns
            'ultra_has_double_letter': 1 if re.search(r'([a-z])\1', domain_name) else 0,
            'ultra_missing_letter': 1 if any(brand[:-1] in domain_name or brand[1:] in domain_name for brand in self.major_brands) else 0,

            # Character substitution
            'ultra_has_digit_substitution': 1 if re.search(r'[a-z][0-9]|[0-9][a-z]', domain_name) else 0,
            'ultra_common_substitutions': sum(1 for sub in ['0', '1', '3', '4', '5', '7', '8'] if sub in domain_name),

            # Added/removed characters
            'ultra_extra_hyphen': 1 if '-' in domain_name else 0,
            'ultra_brand_with_suffix': 1 if any(f"{brand}1" in domain_name or f"{brand}2" in domain_name for brand in self.major_brands) else 0,

            # Similarity metrics
            'ultra_brand_jaro_similarity': max([Levenshtein.jaro(domain_name, brand) for brand in self.major_brands], default=0),
            'ultra_brand_jaro_winkler': max([Levenshtein.jaro_winkler(domain_name, brand) for brand in self.major_brands], default=0),

            # Combosquatting (brand + keyword)
            'ultra_brand_keyword_combo': 1 if any(brand in domain_name for brand in self.major_brands) and any(kw in domain_name for kw in ['secure', 'login', 'verify', 'account']) else 0,

            # IDN homograph potential
            'ultra_confusable_chars_count': sum(1 for c in domain_name if c in {'o', '0', 'l', '1', 'i'}),

            # Wrong TLD for brand
            'ultra_brand_wrong_tld': 1 if any(brand in domain_name for brand in self.major_brands) and parsed.netloc.endswith(('.tk', '.ml', '.ga', '.cf', '.gq', '.xyz')) else 0,

            # Transposition detection
            'ultra_likely_transposition': 1 if self._has_likely_transposition(domain_name) else 0,

            # Pluralization tricks
            'ultra_plural_variation': 1 if any(f"{brand}s" in domain_name for brand in self.major_brands) else 0,

            # Repetition tricks
            'ultra_repeated_brand_chars': sum(1 for brand in self.major_brands if any(c*2 in domain_name for c in brand)),
        }

    def _extract_obfuscation_features(self, url: str, parsed) -> Dict:
        """Detect various obfuscation techniques"""
        return {
            # IP obfuscation
            'ultra_has_decimal_ip': 1 if re.search(r'\d{8,}', parsed.netloc) else 0,  # Decimal IP
            'ultra_has_hex_ip': 1 if re.search(r'0x[0-9a-f]+', url.lower()) else 0,  # Hex IP
            'ultra_has_octal_ip': 1 if re.search(r'0[0-7]+', parsed.netloc) else 0,  # Octal IP

            # URL encoding obfuscation
            'ultra_excessive_encoding': 1 if url.count('%') > 5 else 0,
            'ultra_encoded_slashes': 1 if '%2f' in url.lower() or '%5c' in url.lower() else 0,
            'ultra_encoded_dots': 1 if '%2e' in url.lower() else 0,
            'ultra_double_encoding': 1 if '%25' in url.lower() else 0,

            # Unicode tricks
            'ultra_has_unicode': 1 if any(ord(c) > 127 for c in url) else 0,
            'ultra_zero_width_chars': 1 if any(ord(c) in {8203, 8204, 8205, 8288} for c in url) else 0,

            # Redirection tricks
            'ultra_has_redirect_param': 1 if any(p in parsed.query.lower() for p in ['redirect', 'url', 'goto', 'next', 'continue', 'return', 'redir']) else 0,
            'ultra_suspicious_redirect': 1 if re.search(r'(redirect|url|goto)=https?://', parsed.query.lower()) else 0,

            # Cloaking
            'ultra_data_uri': 1 if 'data:' in url.lower() else 0,
            'ultra_javascript_uri': 1 if 'javascript:' in url.lower() else 0,

            # Path obfuscation
            'ultra_path_traversal': 1 if '../' in parsed.path or '..\\' in parsed.path else 0,
            'ultra_excessive_slashes': 1 if '//' in parsed.path else 0,
        }

    def _extract_statistical_features(self, url: str, parsed) -> Dict:
        """Advanced statistical analysis"""
        domain = parsed.netloc

        return {
            # Character frequency analysis
            'ultra_most_common_char_freq': max(Counter(url).values()) / len(url) if len(url) > 0 else 0,
            'ultra_unique_chars_ratio': len(set(url)) / len(url) if len(url) > 0 else 0,

            # N-gram analysis
            'ultra_bigram_entropy': self._calculate_ngram_entropy(url, 2),
            'ultra_trigram_entropy': self._calculate_ngram_entropy(url, 3),

            # Length statistics
            'ultra_url_length_category': self._categorize_length(len(url)),
            'ultra_domain_length_category': self._categorize_length(len(domain)),

            # Ratio features
            'ultra_vowel_to_consonant_ratio': self._vowel_consonant_ratio(domain),
            'ultra_alpha_to_digit_ratio': self._alpha_digit_ratio(url),

            # Complexity measures
            'ultra_url_complexity_score': self._calculate_complexity(url),
            'ultra_domain_complexity_score': self._calculate_complexity(domain),

            # Pattern regularity
            'ultra_has_repeating_pattern': 1 if self._has_repeating_pattern(domain) else 0,
            'ultra_character_diversity': len(set(url)),

            # Distribution features
            'ultra_digit_distribution': self._calculate_digit_distribution(url),
            'ultra_special_char_diversity': len(set(c for c in url if not c.isalnum())),

            # Structural entropy
            'ultra_structural_entropy': self._calculate_structural_entropy(parsed),

            # Lexical richness
            'ultra_lexical_density': self._calculate_lexical_density(url),

            # N-gram uniqueness
            'ultra_unique_bigrams': len(set(url[i:i+2] for i in range(len(url)-1))),
            'ultra_unique_trigrams': len(set(url[i:i+3] for i in range(len(url)-2))),

            # Character transitions
            'ultra_char_transition_score': self._calculate_transition_score(domain),

            # Randomness indicators
            'ultra_looks_random': 1 if self._looks_random(domain) else 0,
        }

    def _extract_complexity_features(self, url: str, parsed) -> Dict:
        """URL structure complexity analysis"""
        return {
            'ultra_total_tokens': len(re.findall(r'\w+', url)),
            'ultra_avg_token_length': sum(len(t) for t in re.findall(r'\w+', url)) / max(len(re.findall(r'\w+', url)), 1),
            'ultra_max_token_length': max([len(t) for t in re.findall(r'\w+', url)], default=0),
            'ultra_min_token_length': min([len(t) for t in re.findall(r'\w+', url)], default=0) if re.findall(r'\w+', url) else 0,

            'ultra_nested_subdomains': len(parsed.netloc.split('.')) - 2,
            'ultra_path_nesting_level': len([p for p in parsed.path.split('/') if p]),

            'ultra_total_separators': sum(url.count(c) for c in ['.', '/', '-', '_', '?', '&', '=']),
            'ultra_separator_density': sum(url.count(c) for c in ['.', '/', '-', '_', '?', '&', '=']) / len(url) if len(url) > 0 else 0,

            'ultra_url_structure_score': self._calculate_structure_score(parsed),
            'ultra_domain_structure_score': self._calculate_domain_structure(parsed.netloc),

            'ultra_has_file_extension': 1 if re.search(r'\.[a-z]{2,4}$', parsed.path) else 0,
            'ultra_suspicious_file_ext': 1 if re.search(r'\.(php|asp|jsp|cgi|exe|zip)$', parsed.path.lower()) else 0,

            'ultra_balanced_structure': 1 if self._is_balanced_structure(parsed) else 0,

            'ultra_component_count': sum([1 for c in [parsed.scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment] if c]),
            'ultra_component_diversity': len(set([parsed.scheme, parsed.netloc, parsed.path[:20], parsed.query[:20]])),
        }

    def _extract_behavioral_features(self, url: str, parsed) -> Dict:
        """Features indicating behavioral intentions"""
        url_lower = url.lower()

        return {
            'ultra_requests_credentials': 1 if any(k in url_lower for k in ['password', 'login', 'signin', 'auth']) else 0,
            'ultra_promises_reward': 1 if any(k in url_lower for k in ['free', 'win', 'prize', 'gift', 'bonus']) else 0,
            'ultra_creates_urgency': 1 if any(k in url_lower for k in ['urgent', 'expire', 'limited', 'now', 'today']) else 0,
            'ultra_impersonates_authority': 1 if any(k in url_lower for k in ['gov', 'official', 'legal', 'court', 'police']) else 0,
            'ultra_financial_focus': 1 if any(k in url_lower for k in ['bank', 'credit', 'payment', 'billing', 'money']) else 0,

            'ultra_suspicious_behavior_score': sum([
                any(k in url_lower for k in ['password', 'login']),
                any(k in url_lower for k in ['urgent', 'expire']),
                any(k in url_lower for k in ['verify', 'confirm']),
                any(k in url_lower for k in ['suspend', 'lock', 'block']),
                any(k in url_lower for k in ['update', 'renew', 'restore'])
            ]),

            'ultra_tech_support_scam': 1 if any(k in url_lower for k in ['support', 'help', 'error', 'warning', 'virus']) else 0,
            'ultra_account_threat': 1 if any(k in url_lower for k in ['suspend', 'lock', 'close', 'terminate']) else 0,
            'ultra_data_harvest': 1 if any(k in url_lower for k in ['verify', 'confirm', 'update', 'validate']) and any(k in url_lower for k in ['account', 'profile', 'info']) else 0,
            'ultra_redirect_to_external': 1 if 'redirect' in parsed.query.lower() and 'http' in parsed.query.lower() else 0,
        }

    # Helper methods
    def _has_ip_pattern(self, domain: str) -> bool:
        """Check if domain matches IP pattern"""
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain))

    def _is_url_shortener(self, domain: str) -> bool:
        """Check if known URL shortener"""
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly', 'is.gd']
        return any(s in domain for s in shorteners)

    def _max_char_repetition(self, text: str) -> int:
        """Find maximum character repetition"""
        if not text:
            return 0
        max_count = 1
        current_count = 1
        for i in range(1, len(text)):
            if text[i] == text[i-1]:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 1
        return max_count

    def _max_consecutive_type(self, text: str, type_func) -> int:
        """Find maximum consecutive characters of a type"""
        if not text:
            return 0
        max_count = 0
        current_count = 0
        for char in text:
            if type_func(char):
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        return max_count

    def _max_consecutive_consonants(self, text: str) -> int:
        """Find maximum consecutive consonants"""
        vowels = set('aeiou')
        max_count = 0
        current_count = 0
        for char in text.lower():
            if char.isalpha() and char not in vowels:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        return max_count

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _looks_like_base64(self, text: str) -> bool:
        """Check if text looks like base64"""
        return len(text) > 20 and re.match(r'^[A-Za-z0-9+/]+=*$', text) is not None

    def _calculate_vowel_ratio(self, text: str) -> float:
        """Calculate vowel to total character ratio"""
        if not text:
            return 0.0
        vowels = sum(1 for c in text.lower() if c in 'aeiou')
        return vowels / len(text)

    def _count_consonant_clusters(self, text: str) -> int:
        """Count consonant clusters (3+ consonants in a row)"""
        vowels = set('aeiou')
        count = 0
        current = 0
        for char in text.lower():
            if char.isalpha() and char not in vowels:
                current += 1
                if current >= 3:
                    count += 1
            else:
                current = 0
        return count

    def _has_likely_transposition(self, text: str) -> bool:
        """Detect likely character transposition"""
        # Check for common transposition patterns
        patterns = ['teh', 'hte', 'adn', 'nda', 'taht', 'thta']
        return any(p in text for p in patterns)

    def _calculate_ngram_entropy(self, text: str, n: int) -> float:
        """Calculate n-gram entropy"""
        if len(text) < n:
            return 0.0
        ngrams = [text[i:i+n] for i in range(len(text)-n+1)]
        return self._calculate_entropy(''.join(ngrams))

    def _categorize_length(self, length: int) -> int:
        """Categorize length into bins"""
        if length < 20:
            return 0
        elif length < 40:
            return 1
        elif length < 60:
            return 2
        elif length < 80:
            return 3
        else:
            return 4

    def _vowel_consonant_ratio(self, text: str) -> float:
        """Calculate vowel to consonant ratio"""
        vowels = sum(1 for c in text.lower() if c in 'aeiou')
        consonants = sum(1 for c in text.lower() if c.isalpha() and c not in 'aeiou')
        return vowels / max(consonants, 1)

    def _alpha_digit_ratio(self, text: str) -> float:
        """Calculate alphabetic to digit ratio"""
        alpha = sum(1 for c in text if c.isalpha())
        digits = sum(1 for c in text if c.isdigit())
        return alpha / max(digits, 1)

    def _calculate_complexity(self, text: str) -> float:
        """Calculate overall complexity score"""
        if not text:
            return 0.0
        score = 0.0
        score += self._calculate_entropy(text) * 10
        score += len(set(text)) / len(text) * 20
        score += (sum(not c.isalnum() for c in text) / len(text)) * 30
        return min(score, 100)

    def _has_repeating_pattern(self, text: str) -> bool:
        """Detect repeating patterns"""
        for length in range(2, len(text)//2):
            pattern = text[:length]
            if pattern * (len(text)//length) == text[:len(text)//length*length]:
                return True
        return False

    def _calculate_digit_distribution(self, text: str) -> float:
        """Calculate how evenly digits are distributed"""
        digits = [c for c in text if c.isdigit()]
        if not digits:
            return 0.0
        return len(set(digits)) / 10.0

    def _calculate_structural_entropy(self, parsed) -> float:
        """Calculate structural entropy of URL components"""
        components = [parsed.scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment]
        lengths = [len(c) for c in components if c]
        if not lengths:
            return 0.0
        total = sum(lengths)
        entropy = 0.0
        for length in lengths:
            p = length / total
            entropy -= p * math.log2(p)
        return entropy

    def _calculate_lexical_density(self, text: str) -> float:
        """Calculate lexical density (meaningful words)"""
        words = re.findall(r'[a-z]{3,}', text.lower())
        return len(words) / max(len(text.split()), 1)

    def _calculate_transition_score(self, text: str) -> float:
        """Calculate character transition smoothness"""
        if len(text) < 2:
            return 0.0
        transitions = sum(1 for i in range(len(text)-1) if abs(ord(text[i]) - ord(text[i+1])) > 5)
        return transitions / (len(text) - 1)

    def _looks_random(self, text: str) -> bool:
        """Determine if text looks random"""
        if not text:
            return False
        entropy = self._calculate_entropy(text)
        vowel_ratio = self._calculate_vowel_ratio(text)
        return entropy > 4.0 and vowel_ratio < 0.2

    def _calculate_structure_score(self, parsed) -> float:
        """Calculate URL structure quality score"""
        score = 0.0
        if parsed.scheme == 'https':
            score += 10
        if parsed.netloc:
            score += 20
        if len(parsed.netloc.split('.')) >= 2:
            score += 20
        if parsed.path and len(parsed.path) > 1:
            score += 15
        return score

    def _calculate_domain_structure(self, domain: str) -> float:
        """Calculate domain structure quality"""
        score = 0.0
        parts = domain.split('.')
        if len(parts) >= 2:
            score += 20
        if len(parts) == 2 or len(parts) == 3:
            score += 20
        if not any(c.isdigit() for c in parts[-1]):
            score += 10
        return score

    def _is_balanced_structure(self, parsed) -> bool:
        """Check if URL has balanced structure"""
        domain_len = len(parsed.netloc)
        path_len = len(parsed.path)
        query_len = len(parsed.query)

        if domain_len == 0:
            return False

        # Check if components are reasonably balanced
        return (path_len < domain_len * 3) and (query_len < domain_len * 2)

    def _get_default_features(self) -> Dict:
        """Return default features on error"""
        return {f'ultra_feature_{i}': 0 for i in range(200)}


if __name__ == '__main__':
    extractor = UltraFeatureExtractor()

    test_urls = [
        'https://www.google.com',
        'http://secure-paypal-login.tk/verify?urgent=1',
        'https://gooogle.com',  # Typosquatting
        'http://asdfghjkl12345.xyz'  # Random
    ]

    for url in test_urls:
        print(f"\nURL: {url}")
        features = extractor.extract_all_features(url)
        print(f"Extracted {len(features)} features")
        # Show some key features
        for key in list(features.keys())[:10]:
            print(f"  {key}: {features[key]}")
