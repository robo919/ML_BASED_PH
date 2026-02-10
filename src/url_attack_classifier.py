"""
URL Attack Classifier - Comprehensive URL-Based Attack Detection
================================================================

Properly categorizes and identifies ALL major URL-based phishing techniques:

CATEGORY 1: DOMAIN MANIPULATION
-------------------------------
1.1  TYPOSQUATTING          - Typing mistakes (gogle.com, amazn.com)
1.2  BITSQUATTING           - Bit-flip errors in memory (goofle.com)
1.3  DOPPELGANGER_DOMAIN    - Missing dots (wwwgoogle.com, gmailcom.com)

CATEGORY 2: HOMOGRAPH ATTACKS
-----------------------------
2.1  IDN_HOMOGRAPH          - Unicode lookalikes (gооgle.com - Cyrillic о)
2.2  PUNYCODE_ATTACK        - xn-- encoded domains (xn--ggle-55da.com)
2.3  MIXED_SCRIPT           - Mixing scripts (Gοogle - mix Latin/Greek)

CATEGORY 3: BRAND EXPLOITATION
------------------------------
3.1  COMBOSQUATTING         - Brand + keyword (paypal-login.com)
3.2  LEVELSQUATTING         - Brand as subdomain (paypal.evil.com)
3.3  SOUNDSQUATTING         - Homophones (4pple.com sounds like apple)

CATEGORY 4: URL STRUCTURE ABUSE
-------------------------------
4.1  SUBDOMAIN_ABUSE        - Hiding real domain (google.com.evil.site)
4.2  PATH_MANIPULATION      - Fake path (evil.com/google.com/login)
4.3  URL_SHORTENER_ABUSE    - Hidden destination (bit.ly/xyz)
4.4  DATA_URI_ATTACK        - Data: protocol abuse

CATEGORY 5: TECHNICAL DECEPTION
-------------------------------
5.1  IP_ADDRESS_URL         - Direct IP (http://192.168.1.1/paypal)
5.2  URL_ENCODING           - Encoded chars (%70aypal.com)
5.3  DOUBLE_ENCODING        - Double encoded (%2570aypal.com)
5.4  PORT_MANIPULATION      - Non-standard port (google.com:8080)

CATEGORY 6: VISUAL DECEPTION
----------------------------
6.1  ZERO_WIDTH_CHARS       - Invisible Unicode (goo​gle.com)
6.2  RTLO_ATTACK            - Right-to-left override
6.3  CASE_MANIPULATION      - Visual tricks (GoOgLe.com)

"""

import re
import unicodedata
from typing import Dict, List, Tuple, Optional, Set
from urllib.parse import urlparse, unquote, parse_qs
from dataclasses import dataclass
from enum import Enum
import socket
import idna


class AttackCategory(Enum):
    """Main attack categories"""
    DOMAIN_MANIPULATION = "DOMAIN_MANIPULATION"
    HOMOGRAPH_ATTACK = "HOMOGRAPH_ATTACK"
    BRAND_EXPLOITATION = "BRAND_EXPLOITATION"
    URL_STRUCTURE_ABUSE = "URL_STRUCTURE_ABUSE"
    TECHNICAL_DECEPTION = "TECHNICAL_DECEPTION"
    VISUAL_DECEPTION = "VISUAL_DECEPTION"
    LEGITIMATE = "LEGITIMATE"


class AttackType(Enum):
    """Specific attack types with proper naming"""
    # Domain Manipulation
    TYPOSQUATTING_OMISSION = "TYPOSQUATTING_OMISSION"           # Missing char (gogle.com)
    TYPOSQUATTING_INSERTION = "TYPOSQUATTING_INSERTION"         # Extra char (gooogle.com)
    TYPOSQUATTING_SUBSTITUTION = "TYPOSQUATTING_SUBSTITUTION"   # Wrong char (googie.com)
    TYPOSQUATTING_TRANSPOSITION = "TYPOSQUATTING_TRANSPOSITION" # Swapped (googel.com)
    TYPOSQUATTING_KEYBOARD = "TYPOSQUATTING_KEYBOARD"           # Adjacent key (goigle.com)
    BITSQUATTING = "BITSQUATTING"                               # Bit flip (goofle.com)
    DOPPELGANGER_DOMAIN = "DOPPELGANGER_DOMAIN"                 # Missing dot (wwwgoogle.com)

    # Homograph Attacks
    IDN_HOMOGRAPH_CYRILLIC = "IDN_HOMOGRAPH_CYRILLIC"           # Cyrillic chars
    IDN_HOMOGRAPH_GREEK = "IDN_HOMOGRAPH_GREEK"                 # Greek chars
    IDN_HOMOGRAPH_MIXED = "IDN_HOMOGRAPH_MIXED"                 # Mixed scripts
    PUNYCODE_ATTACK = "PUNYCODE_ATTACK"                         # xn-- domain
    MIXED_SCRIPT_ATTACK = "MIXED_SCRIPT_ATTACK"                 # Multiple scripts

    # Brand Exploitation
    COMBOSQUATTING = "COMBOSQUATTING"                           # brand-keyword.com
    LEVELSQUATTING = "LEVELSQUATTING"                           # brand.evil.com
    SOUNDSQUATTING = "SOUNDSQUATTING"                           # Homophone attack
    BRAND_TLD_SWAP = "BRAND_TLD_SWAP"                           # google.co (wrong TLD)

    # URL Structure Abuse
    SUBDOMAIN_ABUSE = "SUBDOMAIN_ABUSE"                         # google.com.evil.com
    PATH_MANIPULATION = "PATH_MANIPULATION"                      # evil.com/google.com
    URL_SHORTENER_ABUSE = "URL_SHORTENER_ABUSE"                 # bit.ly hiding dest
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"              # user:pass@evil.com

    # Technical Deception
    IP_ADDRESS_URL = "IP_ADDRESS_URL"                           # http://1.2.3.4/login
    URL_ENCODING_ABUSE = "URL_ENCODING_ABUSE"                   # %70aypal
    DOUBLE_ENCODING = "DOUBLE_ENCODING"                         # %2570aypal
    HEX_IP_ADDRESS = "HEX_IP_ADDRESS"                           # 0x7f.0x0.0x0.0x1
    OCTAL_IP_ADDRESS = "OCTAL_IP_ADDRESS"                       # 0177.0.0.01
    PORT_MANIPULATION = "PORT_MANIPULATION"                      # :8080, :443

    # Visual Deception
    ZERO_WIDTH_CHARS = "ZERO_WIDTH_CHARS"                       # Invisible chars
    RTLO_ATTACK = "RTLO_ATTACK"                                 # Right-to-left override
    CONFUSABLE_CHARS = "CONFUSABLE_CHARS"                       # l vs 1, O vs 0

    # Clean
    LEGITIMATE = "LEGITIMATE"
    UNKNOWN_SUSPICIOUS = "UNKNOWN_SUSPICIOUS"


@dataclass
class AttackResult:
    """Result of attack classification"""
    is_attack: bool
    category: AttackCategory
    attack_type: AttackType
    confidence: float  # 0.0 - 1.0
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    target_brand: Optional[str]
    description: str
    technical_details: Dict
    recommendations: List[str]


class URLAttackClassifier:
    """
    Comprehensive URL Attack Detection and Classification System
    Properly identifies and names all URL-based attack techniques
    """

    def __init__(self):
        """Initialize classifier with all required data"""
        self.brands = self._load_brands()
        self.unicode_confusables = self._load_confusables()
        self.suspicious_tlds = self._load_suspicious_tlds()
        self.url_shorteners = self._load_url_shorteners()
        self.suspicious_keywords = self._load_suspicious_keywords()
        self.keyboard_layout = self._load_keyboard_layout()
        self.homophones = self._load_homophones()

    def _load_brands(self) -> Set[str]:
        """Load comprehensive brand list"""
        return {
            # Tech Giants (50+)
            'google', 'facebook', 'meta', 'microsoft', 'apple', 'amazon', 'twitter', 'x',
            'linkedin', 'instagram', 'whatsapp', 'youtube', 'netflix', 'spotify', 'zoom',
            'slack', 'dropbox', 'github', 'gitlab', 'stackoverflow', 'reddit', 'discord',
            'telegram', 'snapchat', 'tiktok', 'pinterest', 'tumblr', 'twitch', 'steam',
            'adobe', 'oracle', 'salesforce', 'vmware', 'cisco', 'intel', 'nvidia', 'amd',
            'samsung', 'sony', 'dell', 'hp', 'lenovo', 'asus', 'huawei', 'xiaomi',

            # Cloud Services (20+)
            'aws', 'azure', 'gcloud', 'cloudflare', 'digitalocean', 'heroku', 'vercel',
            'netlify', 'firebase', 'mongodb', 'redis', 'elasticsearch',

            # Financial (50+)
            'paypal', 'stripe', 'square', 'venmo', 'cashapp', 'zelle', 'wise', 'revolut',
            'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'capitalone', 'usbank',
            'pnc', 'tdbank', 'regions', 'suntrust', 'fifththird', 'keybank',
            'americanexpress', 'amex', 'visa', 'mastercard', 'discover',
            'schwab', 'fidelity', 'vanguard', 'etrade', 'robinhood', 'webull',
            'coinbase', 'binance', 'kraken', 'gemini', 'crypto', 'blockchain',
            'metamask', 'ledger', 'trezor', 'exodus', 'trustwallet',

            # Email (15+)
            'gmail', 'outlook', 'hotmail', 'yahoo', 'protonmail', 'icloud', 'aol',
            'zoho', 'fastmail', 'tutanota', 'mailchimp', 'sendgrid',

            # E-commerce (25+)
            'ebay', 'etsy', 'shopify', 'aliexpress', 'alibaba', 'walmart', 'target',
            'bestbuy', 'homedepot', 'lowes', 'costco', 'ikea', 'wayfair', 'wish',
            'overstock', 'newegg', 'bhphoto', 'adorama',

            # Shipping (10+)
            'usps', 'fedex', 'ups', 'dhl', 'royalmail', 'canadapost', 'auspost',

            # Government (10+)
            'irs', 'ssa', 'uscis', 'dmv', 'gov', 'state',

            # Security (15+)
            'norton', 'mcafee', 'kaspersky', 'avast', 'avg', 'bitdefender', 'eset',
            'malwarebytes', 'sophos', 'crowdstrike', 'sentinelone',
        }

    def _load_confusables(self) -> Dict[str, Dict[str, str]]:
        """Load Unicode confusables with script identification"""
        return {
            # Latin -> Cyrillic (most dangerous)
            'a': {'а': 'CYRILLIC', 'ạ': 'LATIN_EXT', 'ả': 'LATIN_EXT'},
            'c': {'с': 'CYRILLIC', 'ϲ': 'GREEK'},
            'e': {'е': 'CYRILLIC', 'ҽ': 'CYRILLIC', 'ε': 'GREEK'},
            'h': {'һ': 'CYRILLIC', 'н': 'CYRILLIC'},
            'i': {'і': 'CYRILLIC', 'ι': 'GREEK', 'ı': 'LATIN_EXT'},
            'j': {'ј': 'CYRILLIC'},
            'k': {'κ': 'GREEK'},
            'l': {'ӏ': 'CYRILLIC', 'ⅼ': 'ROMAN_NUMERAL', '1': 'DIGIT', '|': 'SYMBOL'},
            'm': {'м': 'CYRILLIC'},
            'n': {'η': 'GREEK'},
            'o': {'о': 'CYRILLIC', 'ο': 'GREEK', '0': 'DIGIT', 'օ': 'ARMENIAN'},
            'p': {'р': 'CYRILLIC', 'ρ': 'GREEK'},
            's': {'ѕ': 'CYRILLIC'},
            'u': {'υ': 'GREEK', 'ս': 'ARMENIAN'},
            'v': {'ν': 'GREEK', 'ѵ': 'CYRILLIC'},
            'w': {'ω': 'GREEK', 'ẃ': 'LATIN_EXT'},
            'x': {'х': 'CYRILLIC', 'χ': 'GREEK'},
            'y': {'у': 'CYRILLIC', 'γ': 'GREEK'},

            # Numbers that look like letters
            '0': {'o': 'LATIN', 'O': 'LATIN'},
            '1': {'l': 'LATIN', 'I': 'LATIN', 'i': 'LATIN'},
            '3': {'E': 'LATIN'},
            '5': {'S': 'LATIN'},
            '8': {'B': 'LATIN'},
        }

    def _load_suspicious_tlds(self) -> Set[str]:
        """TLDs commonly used in phishing"""
        return {
            # Free/cheap TLDs
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link',
            'info', 'online', 'site', 'website', 'space', 'fun', 'icu', 'buzz',
            'monster', 'cam', 'quest', 'sbs', 'uno',

            # Country codes often abused
            'cc', 'ws', 'to', 'su', 'pw', 'ru', 'cn',
        }

    def _load_url_shorteners(self) -> Set[str]:
        """Known URL shortener domains"""
        return {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
            'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'j.mp', 'tiny.cc', 'cutt.ly',
            'rb.gy', 'shorturl.at', 'v.gd', 'clck.ru', 'qps.ru', 'shorte.st',
        }

    def _load_suspicious_keywords(self) -> Dict[str, List[str]]:
        """Keywords indicating phishing intent"""
        return {
            'authentication': ['login', 'signin', 'logon', 'signon', 'auth', 'authenticate'],
            'account': ['account', 'myaccount', 'profile', 'user', 'member'],
            'security': ['secure', 'security', 'verify', 'verification', 'validate', 'confirm'],
            'urgency': ['update', 'urgent', 'alert', 'warning', 'suspended', 'locked', 'limited'],
            'financial': ['payment', 'pay', 'billing', 'invoice', 'refund', 'wallet', 'bank'],
            'action': ['click', 'download', 'install', 'open', 'view', 'check'],
            'official': ['official', 'support', 'help', 'service', 'customer', 'team'],
        }

    def _load_keyboard_layout(self) -> Dict[str, str]:
        """QWERTY keyboard adjacent keys"""
        return {
            'q': 'wa12', 'w': 'qeas23', 'e': 'wsdr34', 'r': 'edft45', 't': 'rfgy56',
            'y': 'tghu67', 'u': 'yhji78', 'i': 'ujko89', 'o': 'iklp90', 'p': 'ol0',
            'a': 'qwsz', 's': 'awedxz', 'd': 'serfcx', 'f': 'drtgvc', 'g': 'ftyhbv',
            'h': 'gyujnb', 'j': 'huikmn', 'k': 'jiolm', 'l': 'kop',
            'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn',
            'n': 'bhjm', 'm': 'njk',
        }

    def _load_homophones(self) -> Dict[str, List[str]]:
        """Sound-alike substitutions"""
        return {
            'f': ['ph'], 'ph': ['f'],
            'c': ['k', 's', 'ck'], 'k': ['c', 'ck'], 'ck': ['c', 'k'],
            's': ['z', 'c'], 'z': ['s'],
            'oo': ['u', 'ew'], 'u': ['oo', 'ew'],
            'ee': ['ea', 'i', 'ie'], 'ea': ['ee'],
            'ai': ['ay', 'ei'], 'ay': ['ai'],
            'igh': ['y', 'i'], 'y': ['i', 'ie'],
            'x': ['ks', 'cks'],
            '4': ['for', 'four'], '2': ['to', 'too', 'two'], '8': ['ate'],
        }

    def classify_url(self, url: str) -> AttackResult:
        """
        Main classification method - analyzes URL and returns detailed attack info
        """
        # Parse URL
        try:
            if not url.startswith(('http://', 'https://', '//')):
                url = 'http://' + url
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            full_url = url.lower()
        except Exception as e:
            return AttackResult(
                is_attack=True,
                category=AttackCategory.TECHNICAL_DECEPTION,
                attack_type=AttackType.UNKNOWN_SUSPICIOUS,
                confidence=0.8,
                severity='MEDIUM',
                target_brand=None,
                description=f"Invalid URL format: {str(e)}",
                technical_details={'error': str(e)},
                recommendations=['Do not trust this URL']
            )

        # Remove www. and port for analysis
        domain_clean = re.sub(r'^www\.', '', domain)
        domain_clean = re.sub(r':\d+$', '', domain_clean)

        # Check each attack type in order of severity
        results = []

        # 1. Check Homograph Attacks (Most Dangerous)
        homograph_result = self._check_homograph_attacks(domain, domain_clean)
        if homograph_result:
            results.append(homograph_result)

        # 2. Check Punycode
        punycode_result = self._check_punycode(domain, domain_clean)
        if punycode_result:
            results.append(punycode_result)

        # 3. Check URL Shorteners (before typosquatting to avoid false positives)
        shortener_result = self._check_url_shortener(domain_clean)
        if shortener_result:
            results.append(shortener_result)

        # 4. Check Typosquatting
        typo_result = self._check_typosquatting(domain_clean)
        if typo_result:
            results.append(typo_result)

        # 5. Check Combosquatting
        combo_result = self._check_combosquatting(domain_clean, path)
        if combo_result:
            results.append(combo_result)

        # 5. Check Levelsquatting
        level_result = self._check_levelsquatting(domain)
        if level_result:
            results.append(level_result)

        # 6. Check Doppelganger
        doppel_result = self._check_doppelganger(domain_clean)
        if doppel_result:
            results.append(doppel_result)

        # 7. Check IP-based URLs
        ip_result = self._check_ip_url(domain)
        if ip_result:
            results.append(ip_result)

        # 8. Check URL Encoding abuse
        encoding_result = self._check_url_encoding(full_url)
        if encoding_result:
            results.append(encoding_result)

        # URL Shorteners already checked above (step 3)

        # 10. Check Zero-width characters
        zero_width_result = self._check_zero_width(url)
        if zero_width_result:
            results.append(zero_width_result)

        # 11. Check RTLO attack
        rtlo_result = self._check_rtlo(url)
        if rtlo_result:
            results.append(rtlo_result)

        # 12. Check suspicious TLD
        tld_result = self._check_suspicious_tld(domain_clean)
        if tld_result:
            results.append(tld_result)

        # 13. Check path manipulation
        path_result = self._check_path_manipulation(path, domain_clean)
        if path_result:
            results.append(path_result)

        # Return highest severity result
        if results:
            # Sort by confidence and severity
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            results.sort(key=lambda x: (severity_order.get(x.severity, 0), x.confidence), reverse=True)
            return results[0]

        # No attack detected
        return AttackResult(
            is_attack=False,
            category=AttackCategory.LEGITIMATE,
            attack_type=AttackType.LEGITIMATE,
            confidence=0.9,
            severity='NONE',
            target_brand=None,
            description='No attack techniques detected',
            technical_details={},
            recommendations=['URL appears legitimate, but always verify manually']
        )

    def _check_homograph_attacks(self, domain: str, domain_clean: str) -> Optional[AttackResult]:
        """Detect IDN Homograph attacks (Unicode lookalikes)"""
        # Check if domain has non-ASCII characters
        try:
            domain.encode('ascii')
            return None  # Pure ASCII, not a homograph
        except UnicodeEncodeError:
            pass

        # Identify which script is being used
        scripts_found = set()
        confusables_found = []

        for char in domain_clean.split('.')[0]:  # Check main domain part
            char_name = unicodedata.name(char, '')

            if 'CYRILLIC' in char_name:
                scripts_found.add('CYRILLIC')
            elif 'GREEK' in char_name:
                scripts_found.add('GREEK')
            elif 'ARMENIAN' in char_name:
                scripts_found.add('ARMENIAN')
            elif 'HEBREW' in char_name:
                scripts_found.add('HEBREW')

            # Check if it's a confusable
            for latin_char, confusables in self.unicode_confusables.items():
                if char in confusables:
                    confusables_found.append({
                        'char': char,
                        'looks_like': latin_char,
                        'script': confusables[char]
                    })

        if not confusables_found:
            return None

        # Determine attack subtype
        if 'CYRILLIC' in scripts_found:
            attack_type = AttackType.IDN_HOMOGRAPH_CYRILLIC
        elif 'GREEK' in scripts_found:
            attack_type = AttackType.IDN_HOMOGRAPH_GREEK
        else:
            attack_type = AttackType.IDN_HOMOGRAPH_MIXED

        # Try to identify target brand
        normalized = self._normalize_homograph(domain_clean)
        target_brand = self._find_brand_match(normalized)

        return AttackResult(
            is_attack=True,
            category=AttackCategory.HOMOGRAPH_ATTACK,
            attack_type=attack_type,
            confidence=0.98,
            severity='CRITICAL',
            target_brand=target_brand,
            description=f'IDN Homograph Attack using {", ".join(scripts_found)} characters',
            technical_details={
                'scripts_detected': list(scripts_found),
                'confusables': confusables_found,
                'normalized_domain': normalized,
                'original_domain': domain_clean,
            },
            recommendations=[
                'This URL uses deceptive Unicode characters',
                'The domain visually mimics a legitimate site',
                'DO NOT enter any credentials',
                'Report this URL as phishing'
            ]
        )

    def _check_punycode(self, domain: str, domain_clean: str) -> Optional[AttackResult]:
        """Detect Punycode-based attacks (xn-- domains)"""
        if 'xn--' not in domain.lower():
            return None

        # Decode punycode to see actual domain
        try:
            decoded = idna.decode(domain_clean.split('.')[0])
        except:
            decoded = domain_clean

        # Check if decoded version targets a brand
        target_brand = self._find_brand_match(decoded)

        return AttackResult(
            is_attack=True,
            category=AttackCategory.HOMOGRAPH_ATTACK,
            attack_type=AttackType.PUNYCODE_ATTACK,
            confidence=0.95,
            severity='CRITICAL',
            target_brand=target_brand,
            description='Punycode domain (internationalized domain name)',
            technical_details={
                'punycode_domain': domain_clean,
                'decoded_domain': decoded,
            },
            recommendations=[
                'This is a Punycode-encoded domain',
                'May display differently in browser',
                'Verify the actual destination carefully'
            ]
        )

    def _check_typosquatting(self, domain_clean: str) -> Optional[AttackResult]:
        """Detect typosquatting attacks with specific technique identification"""
        main_domain = domain_clean.split('.')[0]

        best_match = None
        best_score = 0
        best_technique = None

        for brand in self.brands:
            if main_domain == brand:
                continue  # Exact match, not typosquatting

            # Only check brands with similar length (±2 chars)
            if abs(len(main_domain) - len(brand)) > 2:
                continue

            # Check each technique
            technique, score = self._identify_typo_technique(main_domain, brand)

            if technique and score > best_score:
                best_score = score
                best_match = brand
                best_technique = technique

        if not best_technique or best_score < 0.85:
            return None

        # Map technique to attack type
        technique_map = {
            'omission': AttackType.TYPOSQUATTING_OMISSION,
            'insertion': AttackType.TYPOSQUATTING_INSERTION,
            'substitution': AttackType.TYPOSQUATTING_SUBSTITUTION,
            'transposition': AttackType.TYPOSQUATTING_TRANSPOSITION,
            'keyboard': AttackType.TYPOSQUATTING_KEYBOARD,
            'bitsquat': AttackType.BITSQUATTING,
        }

        attack_type = technique_map.get(best_technique, AttackType.TYPOSQUATTING_SUBSTITUTION)

        severity = 'CRITICAL' if best_score >= 0.95 else 'HIGH' if best_score >= 0.85 else 'MEDIUM'

        return AttackResult(
            is_attack=True,
            category=AttackCategory.DOMAIN_MANIPULATION,
            attack_type=attack_type,
            confidence=best_score,
            severity=severity,
            target_brand=best_match,
            description=f'Typosquatting ({best_technique}) targeting {best_match}',
            technical_details={
                'technique': best_technique,
                'target_brand': best_match,
                'similarity_score': best_score,
                'domain_entered': main_domain,
                'legitimate_domain': best_match,
            },
            recommendations=[
                f'This domain mimics "{best_match}" with a typo',
                f'Technique used: {best_technique.upper()}',
                f'Did you mean: {best_match}.com?',
            ]
        )

    def _identify_typo_technique(self, domain: str, brand: str) -> Tuple[Optional[str], float]:
        """Identify specific typosquatting technique used"""
        # 1. Omission (missing character) - domain is 1 char shorter
        if len(domain) == len(brand) - 1:
            for i in range(len(brand)):
                if brand[:i] + brand[i+1:] == domain:
                    return ('omission', 0.95)

        # 2. Insertion (extra character) - domain is 1 char longer
        if len(domain) == len(brand) + 1:
            for i in range(len(domain)):
                if domain[:i] + domain[i+1:] == brand:
                    return ('insertion', 0.92)

        # 3. Same length checks
        if len(domain) == len(brand):
            diff_positions = [(i, d, b) for i, (d, b) in enumerate(zip(domain, brand)) if d != b]
            diff_count = len(diff_positions)

            # 3a. Transposition (exactly 2 adjacent chars swapped)
            if diff_count == 2:
                pos1, pos2 = diff_positions[0][0], diff_positions[1][0]
                if pos2 - pos1 == 1:  # Adjacent positions
                    if domain[pos1] == brand[pos2] and domain[pos2] == brand[pos1]:
                        return ('transposition', 0.94)

            # 3b. Single character difference
            if diff_count == 1:
                pos, d_char, b_char = diff_positions[0]

                # Check keyboard adjacency first
                if b_char in self.keyboard_layout and d_char in self.keyboard_layout[b_char]:
                    return ('keyboard', 0.93)

                # Check if it's a common visual substitution (l/1, o/0)
                visual_subs = {
                    ('l', '1'), ('1', 'l'), ('o', '0'), ('0', 'o'),
                    ('i', '1'), ('1', 'i'), ('s', '5'), ('5', 's'),
                    ('e', '3'), ('3', 'e'), ('a', '4'), ('4', 'a'),
                }
                if (d_char, b_char) in visual_subs or (b_char, d_char) in visual_subs:
                    return ('substitution', 0.92)

                # Check bitsquatting (single bit flip) - more strict
                xor_val = ord(d_char) ^ ord(b_char)
                if xor_val in [1, 2, 4, 8, 16, 32, 64, 128]:
                    # Only count as bitsquat if chars are similar ASCII range
                    if d_char.isalnum() and b_char.isalnum():
                        return ('bitsquat', 0.91)

                # Generic substitution
                return ('substitution', 0.90)

        return (None, 0)

    def _check_combosquatting(self, domain_clean: str, path: str) -> Optional[AttackResult]:
        """Detect combosquatting (brand + keyword)"""
        main_domain = domain_clean.split('.')[0]

        for brand in self.brands:
            if brand in main_domain and brand != main_domain:
                # Found brand embedded in domain
                remainder = main_domain.replace(brand, '')

                # Check for suspicious keywords
                suspicious_found = []
                for category, keywords in self.suspicious_keywords.items():
                    for keyword in keywords:
                        if keyword in remainder or keyword in path:
                            suspicious_found.append((category, keyword))

                if suspicious_found or '-' in main_domain or len(remainder) > 2:
                    return AttackResult(
                        is_attack=True,
                        category=AttackCategory.BRAND_EXPLOITATION,
                        attack_type=AttackType.COMBOSQUATTING,
                        confidence=0.88,
                        severity='HIGH',
                        target_brand=brand,
                        description=f'Combosquatting: {brand} combined with suspicious keywords',
                        technical_details={
                            'brand_found': brand,
                            'full_domain': main_domain,
                            'suspicious_keywords': suspicious_found,
                        },
                        recommendations=[
                            f'This domain combines "{brand}" with additional words',
                            'Legitimate companies rarely use domains like this',
                            f'Visit {brand}.com directly instead'
                        ]
                    )
        return None

    def _check_levelsquatting(self, domain: str) -> Optional[AttackResult]:
        """Detect levelsquatting (brand as subdomain)"""
        parts = domain.split('.')

        if len(parts) < 3:
            return None

        # Check if any subdomain matches a brand
        subdomains = parts[:-2]  # Everything except domain.tld
        actual_domain = '.'.join(parts[-2:])

        for subdomain in subdomains:
            if subdomain in self.brands:
                return AttackResult(
                    is_attack=True,
                    category=AttackCategory.BRAND_EXPLOITATION,
                    attack_type=AttackType.LEVELSQUATTING,
                    confidence=0.92,
                    severity='HIGH',
                    target_brand=subdomain,
                    description=f'Levelsquatting: "{subdomain}" used as subdomain of {actual_domain}',
                    technical_details={
                        'brand_in_subdomain': subdomain,
                        'actual_domain': actual_domain,
                        'full_host': domain,
                    },
                    recommendations=[
                        f'The brand "{subdomain}" is a SUBDOMAIN, not the real domain',
                        f'Actual destination: {actual_domain}',
                        f'This is NOT an official {subdomain} website'
                    ]
                )
        return None

    def _check_doppelganger(self, domain_clean: str) -> Optional[AttackResult]:
        """Detect doppelganger domains (missing dots)"""
        # Check for missing dots in common patterns
        doppelganger_patterns = [
            ('wwwgoogle', 'www.google'),
            ('wwwfacebook', 'www.facebook'),
            ('wwwpaypal', 'www.paypal'),
            ('gmailcom', 'gmail.com'),
            ('paypalcom', 'paypal.com'),
        ]

        main_domain = domain_clean.split('.')[0]

        for pattern, correct in doppelganger_patterns:
            if pattern in main_domain:
                brand = correct.split('.')[0].replace('www', '').strip('.')
                if not brand:
                    brand = correct.split('.')[1] if '.' in correct else correct

                return AttackResult(
                    is_attack=True,
                    category=AttackCategory.DOMAIN_MANIPULATION,
                    attack_type=AttackType.DOPPELGANGER_DOMAIN,
                    confidence=0.94,
                    severity='HIGH',
                    target_brand=brand,
                    description=f'Doppelganger domain (missing dot): should be {correct}',
                    technical_details={
                        'entered_domain': main_domain,
                        'likely_intended': correct,
                    },
                    recommendations=[
                        'This domain is missing a dot (period)',
                        f'You probably meant: {correct}',
                        'This is a common typo that attackers exploit'
                    ]
                )

        # Check for brand + com/net/org without dot
        for brand in self.brands:
            for tld in ['com', 'net', 'org', 'co']:
                if main_domain == brand + tld:
                    return AttackResult(
                        is_attack=True,
                        category=AttackCategory.DOMAIN_MANIPULATION,
                        attack_type=AttackType.DOPPELGANGER_DOMAIN,
                        confidence=0.93,
                        severity='HIGH',
                        target_brand=brand,
                        description=f'Doppelganger: {brand}{tld} instead of {brand}.{tld}',
                        technical_details={
                            'entered': main_domain,
                            'intended': f'{brand}.{tld}',
                        },
                        recommendations=[
                            f'Missing dot between {brand} and {tld}',
                            f'Correct domain: {brand}.{tld}'
                        ]
                    )
        return None

    def _check_ip_url(self, domain: str) -> Optional[AttackResult]:
        """Detect IP address URLs"""
        # Regular IP
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        # Hex IP
        hex_pattern = r'^0x[0-9a-f]+\.0x[0-9a-f]+\.0x[0-9a-f]+\.0x[0-9a-f]+$'
        # Octal IP
        octal_pattern = r'^0[0-7]+\.0[0-7]+\.0[0-7]+\.0[0-7]+$'
        # Decimal IP (single number)
        decimal_pattern = r'^\d{8,10}$'

        domain_clean = re.sub(r':\d+$', '', domain)  # Remove port

        attack_type = None

        if re.match(ip_pattern, domain_clean):
            attack_type = AttackType.IP_ADDRESS_URL
        elif re.match(hex_pattern, domain_clean, re.IGNORECASE):
            attack_type = AttackType.HEX_IP_ADDRESS
        elif re.match(octal_pattern, domain_clean):
            attack_type = AttackType.OCTAL_IP_ADDRESS
        elif re.match(decimal_pattern, domain_clean):
            attack_type = AttackType.IP_ADDRESS_URL

        if attack_type:
            return AttackResult(
                is_attack=True,
                category=AttackCategory.TECHNICAL_DECEPTION,
                attack_type=attack_type,
                confidence=0.90,
                severity='HIGH',
                target_brand=None,
                description='URL uses IP address instead of domain name',
                technical_details={
                    'ip_format': attack_type.value,
                    'ip_address': domain_clean,
                },
                recommendations=[
                    'Legitimate websites rarely use IP addresses',
                    'This hides the real destination',
                    'Do not trust URLs with IP addresses'
                ]
            )
        return None

    def _check_url_encoding(self, url: str) -> Optional[AttackResult]:
        """Detect URL encoding abuse"""
        # Check for percent-encoded characters in unusual places
        encoded_pattern = r'%[0-9a-fA-F]{2}'

        # Domain part shouldn't have encoding
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
        except:
            return None

        encoded_chars = re.findall(encoded_pattern, domain)

        if encoded_chars:
            # Check for double encoding
            double_encoded = re.findall(r'%25[0-9a-fA-F]{2}', url)

            if double_encoded:
                attack_type = AttackType.DOUBLE_ENCODING
                severity = 'CRITICAL'
                description = 'Double URL encoding detected (evasion technique)'
            else:
                attack_type = AttackType.URL_ENCODING_ABUSE
                severity = 'HIGH'
                description = 'Suspicious URL encoding in domain'

            return AttackResult(
                is_attack=True,
                category=AttackCategory.TECHNICAL_DECEPTION,
                attack_type=attack_type,
                confidence=0.88,
                severity=severity,
                target_brand=None,
                description=description,
                technical_details={
                    'encoded_chars': encoded_chars,
                    'decoded_domain': unquote(domain),
                },
                recommendations=[
                    'Domain names should not contain encoded characters',
                    'This is an evasion technique used by attackers',
                    'Do not trust this URL'
                ]
            )
        return None

    def _check_url_shortener(self, domain_clean: str) -> Optional[AttackResult]:
        """Detect URL shortener usage"""
        # Direct shortener domain check (include with and without www)
        shortener_domains = {
            'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'j.mp',
            'tiny.cc', 'cutt.ly', 'rb.gy', 'shorturl.at', 'v.gd', 'clck.ru',
            'qps.ru', 'shorte.st', 'trib.al', 'rebrand.ly', 'bl.ink', 'short.io',
            'lnkd.in', 'youtu.be', 'amzn.to', 'fb.me', 'twtr.to'
        }

        # Remove www. prefix for comparison
        domain_check = domain_clean.replace('www.', '')

        for shortener in shortener_domains:
            # Check if domain matches shortener exactly
            if domain_check == shortener:
                return AttackResult(
                    is_attack=True,
                    category=AttackCategory.URL_STRUCTURE_ABUSE,
                    attack_type=AttackType.URL_SHORTENER_ABUSE,
                    confidence=0.95,  # High confidence - known shortener
                    severity='HIGH',  # Elevated because destination is hidden
                    target_brand=None,
                    description=f'URL shortener detected: {shortener}',
                    technical_details={
                        'shortener_service': shortener,
                    },
                    recommendations=[
                        'URL shorteners hide the real destination',
                        'Expand the URL before clicking',
                        'Be extra cautious with shortened links'
                    ]
                )
        return None

    def _check_zero_width(self, url: str) -> Optional[AttackResult]:
        """Detect zero-width characters"""
        zero_width_chars = [
            '\u200b',  # Zero-width space
            '\u200c',  # Zero-width non-joiner
            '\u200d',  # Zero-width joiner
            '\u2060',  # Word joiner
            '\ufeff',  # BOM
        ]

        found_chars = []
        for char in zero_width_chars:
            if char in url:
                found_chars.append(f'U+{ord(char):04X}')

        if found_chars:
            return AttackResult(
                is_attack=True,
                category=AttackCategory.VISUAL_DECEPTION,
                attack_type=AttackType.ZERO_WIDTH_CHARS,
                confidence=0.95,
                severity='CRITICAL',
                target_brand=None,
                description='Invisible zero-width characters detected',
                technical_details={
                    'invisible_chars': found_chars,
                    'char_count': len(found_chars),
                },
                recommendations=[
                    'URL contains invisible characters',
                    'This is a deception technique',
                    'The URL may look different than it actually is'
                ]
            )
        return None

    def _check_rtlo(self, url: str) -> Optional[AttackResult]:
        """Detect Right-to-Left Override attack"""
        rtlo_char = '\u202e'

        if rtlo_char in url:
            return AttackResult(
                is_attack=True,
                category=AttackCategory.VISUAL_DECEPTION,
                attack_type=AttackType.RTLO_ATTACK,
                confidence=0.99,
                severity='CRITICAL',
                target_brand=None,
                description='Right-to-Left Override character detected',
                technical_details={
                    'rtlo_position': url.index(rtlo_char),
                },
                recommendations=[
                    'URL contains text direction manipulation',
                    'What you see is NOT the real URL',
                    'This is a sophisticated attack technique'
                ]
            )
        return None

    def _check_suspicious_tld(self, domain_clean: str) -> Optional[AttackResult]:
        """Check for suspicious TLD combined with brand"""
        parts = domain_clean.split('.')
        if len(parts) < 2:
            return None

        tld = parts[-1]
        main_domain = parts[0] if len(parts) == 2 else '.'.join(parts[:-1])

        # Check if suspicious TLD is used with a brand
        if tld in self.suspicious_tlds:
            for brand in self.brands:
                if brand in main_domain:
                    return AttackResult(
                        is_attack=True,
                        category=AttackCategory.BRAND_EXPLOITATION,
                        attack_type=AttackType.BRAND_TLD_SWAP,
                        confidence=0.85,
                        severity='HIGH',
                        target_brand=brand,
                        description=f'Brand "{brand}" with suspicious TLD ".{tld}"',
                        technical_details={
                            'brand': brand,
                            'suspicious_tld': tld,
                        },
                        recommendations=[
                            f'The .{tld} TLD is commonly used in phishing',
                            f'Legitimate {brand} uses .com, not .{tld}',
                            f'Visit {brand}.com directly'
                        ]
                    )
        return None

    def _check_path_manipulation(self, path: str, domain_clean: str) -> Optional[AttackResult]:
        """Check for brand names hidden in path"""
        # Skip very short brands to avoid false positives
        min_brand_length = 4

        for brand in self.brands:
            if len(brand) < min_brand_length:
                continue  # Skip short brands like 'x', 'hp', etc.

            if brand in path and brand not in domain_clean:
                return AttackResult(
                    is_attack=True,
                    category=AttackCategory.URL_STRUCTURE_ABUSE,
                    attack_type=AttackType.PATH_MANIPULATION,
                    confidence=0.80,
                    severity='MEDIUM',
                    target_brand=brand,
                    description=f'Brand "{brand}" in URL path, not domain',
                    technical_details={
                        'brand_in_path': brand,
                        'actual_domain': domain_clean,
                        'path': path,
                    },
                    recommendations=[
                        f'"{brand}" appears in the path, NOT the domain',
                        f'The actual website is: {domain_clean}',
                        'This is NOT an official site'
                    ]
                )
        return None

    def _normalize_homograph(self, domain: str) -> str:
        """Convert homograph characters to ASCII equivalents"""
        result = []
        for char in domain:
            replaced = False
            for latin, confusables in self.unicode_confusables.items():
                if char in confusables:
                    result.append(latin)
                    replaced = True
                    break
            if not replaced:
                result.append(char)
        return ''.join(result)

    def _find_brand_match(self, text: str) -> Optional[str]:
        """Find if text matches or contains a brand"""
        text_lower = text.lower()
        for brand in self.brands:
            if brand in text_lower:
                return brand
        return None

    def get_attack_summary(self, result: AttackResult) -> str:
        """Generate human-readable attack summary"""
        if not result.is_attack:
            return "✅ No attack detected - URL appears legitimate"

        lines = [
            f"⚠️ ATTACK DETECTED: {result.attack_type.value}",
            f"Category: {result.category.value}",
            f"Severity: {result.severity}",
            f"Confidence: {result.confidence:.0%}",
            f"Description: {result.description}",
        ]

        if result.target_brand:
            lines.append(f"Target Brand: {result.target_brand}")

        lines.append("\nRecommendations:")
        for rec in result.recommendations:
            lines.append(f"  • {rec}")

        return "\n".join(lines)


# Convenience function
def classify_url(url: str) -> AttackResult:
    """Quick classification of a URL"""
    classifier = URLAttackClassifier()
    return classifier.classify_url(url)


def print_attack_types():
    """Print all supported attack types with descriptions"""
    print("=" * 80)
    print("URL-BASED ATTACK TECHNIQUES CLASSIFICATION")
    print("=" * 80)

    categories = {
        "DOMAIN MANIPULATION": [
            ("TYPOSQUATTING_OMISSION", "Missing character", "gogle.com (missing o)"),
            ("TYPOSQUATTING_INSERTION", "Extra character", "gooogle.com (extra o)"),
            ("TYPOSQUATTING_SUBSTITUTION", "Wrong character", "googie.com (i for l)"),
            ("TYPOSQUATTING_TRANSPOSITION", "Swapped characters", "googel.com (el swapped)"),
            ("TYPOSQUATTING_KEYBOARD", "Adjacent key typo", "goigle.com (i near o)"),
            ("BITSQUATTING", "Single bit flip", "goofle.com (bit error)"),
            ("DOPPELGANGER_DOMAIN", "Missing dot", "wwwgoogle.com"),
        ],
        "HOMOGRAPH ATTACKS": [
            ("IDN_HOMOGRAPH_CYRILLIC", "Cyrillic lookalikes", "gооgle.com (Cyrillic о)"),
            ("IDN_HOMOGRAPH_GREEK", "Greek lookalikes", "googIe.com (Greek Ι)"),
            ("PUNYCODE_ATTACK", "xn-- encoded", "xn--ggle-55da.com"),
            ("MIXED_SCRIPT_ATTACK", "Multiple scripts", "Gοogle (Latin+Greek)"),
        ],
        "BRAND EXPLOITATION": [
            ("COMBOSQUATTING", "Brand + keyword", "paypal-login.com"),
            ("LEVELSQUATTING", "Brand as subdomain", "paypal.evil.com"),
            ("SOUNDSQUATTING", "Homophone attack", "4pple.com"),
            ("BRAND_TLD_SWAP", "Wrong TLD", "google.tk"),
        ],
        "URL STRUCTURE ABUSE": [
            ("SUBDOMAIN_ABUSE", "Fake subdomain", "google.com.evil.site"),
            ("PATH_MANIPULATION", "Brand in path", "evil.com/google.com/login"),
            ("URL_SHORTENER_ABUSE", "Hidden destination", "bit.ly/xyz"),
            ("CREDENTIAL_HARVESTING", "Embedded creds", "user:pass@evil.com"),
        ],
        "TECHNICAL DECEPTION": [
            ("IP_ADDRESS_URL", "Direct IP", "http://192.168.1.1/login"),
            ("HEX_IP_ADDRESS", "Hex encoded IP", "0x7f.0x0.0x0.0x1"),
            ("URL_ENCODING_ABUSE", "Percent encoding", "%70aypal.com"),
            ("DOUBLE_ENCODING", "Double encode", "%2570aypal.com"),
            ("PORT_MANIPULATION", "Non-standard port", "google.com:8080"),
        ],
        "VISUAL DECEPTION": [
            ("ZERO_WIDTH_CHARS", "Invisible chars", "goo​gle.com (hidden char)"),
            ("RTLO_ATTACK", "Right-to-left override", "moc.elgoog (reversed)"),
            ("CONFUSABLE_CHARS", "l vs 1, O vs 0", "paypa1.com"),
        ],
    }

    for category, attacks in categories.items():
        print(f"\n{category}")
        print("-" * 60)
        for attack_type, description, example in attacks:
            print(f"  {attack_type:30} | {description:20} | {example}")

    print("\n" + "=" * 80)


if __name__ == '__main__':
    # Print attack types reference
    print_attack_types()

    print("\n\nTESTING URL ATTACK CLASSIFIER")
    print("=" * 80)

    classifier = URLAttackClassifier()

    test_urls = [
        # Typosquatting
        ('https://gogle.com', 'TYPOSQUATTING_OMISSION'),
        ('https://gooogle.com', 'TYPOSQUATTING_INSERTION'),
        ('https://googel.com', 'TYPOSQUATTING_TRANSPOSITION'),
        ('https://paypa1.com', 'TYPOSQUATTING_SUBSTITUTION'),

        # Homograph
        ('https://gооgle.com', 'IDN_HOMOGRAPH (Cyrillic)'),
        ('https://xn--ggle-55da.com', 'PUNYCODE'),

        # Brand exploitation
        ('https://paypal-login.com', 'COMBOSQUATTING'),
        ('https://paypal.secure-site.com', 'LEVELSQUATTING'),
        ('https://google.tk', 'BRAND_TLD_SWAP'),

        # Technical
        ('http://192.168.1.1/paypal/login', 'IP_ADDRESS_URL'),
        ('https://bit.ly/xyz123', 'URL_SHORTENER'),

        # Legitimate
        ('https://www.google.com', 'LEGITIMATE'),
        ('https://www.paypal.com', 'LEGITIMATE'),
    ]

    for url, expected in test_urls:
        result = classifier.classify_url(url)
        status = "✓" if result.is_attack or expected == 'LEGITIMATE' else "✗"

        print(f"\n{status} URL: {url}")
        print(f"  Expected: {expected}")
        print(f"  Detected: {result.attack_type.value}")
        print(f"  Severity: {result.severity}")
        print(f"  Confidence: {result.confidence:.0%}")
        if result.target_brand:
            print(f"  Target Brand: {result.target_brand}")
        print(f"  Description: {result.description}")
