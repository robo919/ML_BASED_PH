"""
ULTIMATE Phishing Predictor - Next Generation Detection System
Integrates:
- Advanced domain validation (DNS, WHOIS, syntax)
- Ultra feature extraction (200+ features)
- ML models
- Pattern detection
- Real-time threat intelligence
- Google Safe Browsing API (FREE - powers Chrome/Firefox)
- VirusTotal API (FREE - 70+ scanners)
- urlscan.io API (FREE - sandbox analysis)
- PhishTank database
- Built-in phishing signature database
- Intelligent classification

This is the BRAIN of the advanced phishing detection system!

API Keys (all FREE):
- Set in .env file or as environment variables
- GOOGLE_SAFE_BROWSING_KEY: https://console.cloud.google.com/apis/credentials
- VIRUSTOTAL_API_KEY: https://www.virustotal.com/gui/join-us
- URLSCAN_API_KEY: https://urlscan.io/user/signup
- PHISHTANK_API_KEY: https://www.phishtank.com/api_register.php
"""

import os
import sys
import logging
import requests
import base64
import json
from typing import Dict, List, Optional
from datetime import datetime
from urllib.parse import quote

# Load .env file if exists
def load_env_file():
    """Load API keys from .env file"""
    env_paths = ['.env', '../.env', os.path.join(os.path.dirname(__file__), '..', '.env')]
    for env_path in env_paths:
        if os.path.exists(env_path):
            try:
                with open(env_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            if value and key not in os.environ:
                                os.environ[key] = value
            except:
                pass
            break

load_env_file()

# Import all detection modules
try:
    from advanced_domain_validator import AdvancedDomainValidator
    from ultra_feature_extractor import UltraFeatureExtractor
    from predictor import PhishingPredictor
    from enhanced_pattern_detector import EnhancedPatternDetector
    from advanced_typosquatting_detector import AdvancedTyposquattingDetector
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some modules not available: {e}")
    MODULES_AVAILABLE = False

# Import phishing database (local, no API)
try:
    from phishing_database import PhishingDatabase, get_phishing_database
    PHISHING_DB_AVAILABLE = True
except ImportError:
    PHISHING_DB_AVAILABLE = False
    print("Warning: Local phishing database not available")

# Import PhishTank checker (no API key required)
try:
    from phishtank_checker import PhishTankChecker, get_phishtank_checker
    PHISHTANK_AVAILABLE = True
except ImportError:
    PHISHTANK_AVAILABLE = False
    print("Warning: PhishTank checker not available")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================================================================
# EXTERNAL API CHECKERS (Google Safe Browsing, VirusTotal, urlscan.io)
# =============================================================================

class GoogleSafeBrowsingChecker:
    """Google Safe Browsing API - FREE, powers Chrome/Firefox, protects 4B+ devices"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get('GOOGLE_SAFE_BROWSING_KEY')
        self.api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def check_url(self, url: str) -> Dict:
        """Check URL against Google Safe Browsing"""
        result = {'checked': False, 'is_threat': False, 'threat_type': None, 'error': None}

        if not self.api_key:
            result['error'] = 'No API key (get free at console.cloud.google.com)'
            return result

        try:
            payload = {
                "client": {"clientId": "phishing-detector", "clientVersion": "3.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }

            response = requests.post(
                f"{self.api_url}?key={self.api_key}",
                json=payload,
                timeout=10
            )
            result['checked'] = True

            if response.status_code == 200:
                data = response.json()
                if data.get('matches'):
                    result['is_threat'] = True
                    result['threat_type'] = data['matches'][0].get('threatType', 'UNKNOWN')
                    result['details'] = data['matches']
            else:
                result['error'] = f'HTTP {response.status_code}'

        except Exception as e:
            result['error'] = str(e)
            logger.warning(f"Google Safe Browsing error: {e}")

        return result


class VirusTotalChecker:
    """VirusTotal API - FREE (500/day), 70+ antivirus scanners"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get('VIRUSTOTAL_API_KEY')
        self.api_url = "https://www.virustotal.com/api/v3/urls"

    def check_url(self, url: str) -> Dict:
        """Check URL against VirusTotal (70+ scanners)"""
        result = {'checked': False, 'malicious_count': 0, 'suspicious_count': 0, 'total_scanners': 0, 'error': None}

        if not self.api_key:
            result['error'] = 'No API key (get free at virustotal.com)'
            return result

        try:
            # URL ID for VirusTotal API v3
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')

            headers = {'x-apikey': self.api_key}
            response = requests.get(
                f"{self.api_url}/{url_id}",
                headers=headers,
                timeout=15
            )
            result['checked'] = True

            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                result['malicious_count'] = stats.get('malicious', 0)
                result['suspicious_count'] = stats.get('suspicious', 0)
                result['total_scanners'] = sum(stats.values())
                result['stats'] = stats
            elif response.status_code == 404:
                result['not_found'] = True  # URL not scanned yet
            else:
                result['error'] = f'HTTP {response.status_code}'

        except Exception as e:
            result['error'] = str(e)
            logger.warning(f"VirusTotal error: {e}")

        return result


class UrlscanChecker:
    """urlscan.io API - FREE tier, sandbox analysis, 1500+ brand detection"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get('URLSCAN_API_KEY')
        self.search_url = "https://urlscan.io/api/v1/search/"

    def check_url(self, url: str) -> Dict:
        """Check URL against urlscan.io"""
        result = {'checked': False, 'is_malicious': False, 'score': 0, 'error': None}

        if not self.api_key:
            result['error'] = 'No API key (get free at urlscan.io)'
            return result

        try:
            headers = {'API-Key': self.api_key}
            # Search for existing scans
            search_query = f"page.url:\"{url}\""
            response = requests.get(
                f"{self.search_url}?q={quote(search_query)}",
                headers=headers,
                timeout=10
            )
            result['checked'] = True

            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])

                if results:
                    latest = results[0]
                    result['scan_id'] = latest.get('_id')
                    verdicts = latest.get('verdicts', {})
                    overall = verdicts.get('overall', {})
                    result['score'] = overall.get('score', 0)
                    result['is_malicious'] = overall.get('malicious', False)
                    result['categories'] = overall.get('categories', [])
                else:
                    result['not_found'] = True
            else:
                result['error'] = f'HTTP {response.status_code}'

        except Exception as e:
            result['error'] = str(e)
            logger.warning(f"urlscan.io error: {e}")

        return result


class UltimatePhishingPredictor:
    """
    Ultimate ML-based phishing detector with comprehensive analysis

    Detection Pipeline:
    1. Domain Validation (Is it real? Random? Fake?)
    2. Ultra Feature Extraction (200+ features)
    3. ML Model Prediction
    4. Pattern Analysis
    5. Threat Intelligence
    6. Final Verdict with Detailed Report
    """

    def __init__(self, models_dir: str = 'models'):
        """Initialize all detection systems"""
        logger.info("Initializing Ultimate Phishing Predictor...")

        # Initialize all subsystems
        self.domain_validator = AdvancedDomainValidator()
        self.ultra_feature_extractor = UltraFeatureExtractor()
        self.ml_predictor = PhishingPredictor(models_dir=models_dir)
        self.pattern_detector = EnhancedPatternDetector()
        self.typosquatting_detector = AdvancedTyposquattingDetector()

        # Initialize phishing database (local, no API needed)
        self.phishing_db = None
        if PHISHING_DB_AVAILABLE:
            self.phishing_db = get_phishing_database()
            logger.info("✓ Local phishing database loaded")

        # Initialize PhishTank checker
        self.phishtank_checker = None
        if PHISHTANK_AVAILABLE:
            phishtank_key = os.environ.get('PHISHTANK_API_KEY')
            self.phishtank_checker = get_phishtank_checker(api_key=phishtank_key)
            logger.info("✓ PhishTank checker initialized")

        # Initialize external API checkers (all FREE)
        self.google_checker = GoogleSafeBrowsingChecker()
        self.virustotal_checker = VirusTotalChecker()
        self.urlscan_checker = UrlscanChecker()

        # Log API status
        logger.info("External API Status:")
        logger.info(f"  Google Safe Browsing: {'✓ Ready' if self.google_checker.api_key else '✗ No key (get free at console.cloud.google.com)'}")
        logger.info(f"  VirusTotal: {'✓ Ready' if self.virustotal_checker.api_key else '✗ No key (get free at virustotal.com)'}")
        logger.info(f"  urlscan.io: {'✓ Ready' if self.urlscan_checker.api_key else '✗ No key (get free at urlscan.io)'}")

        logger.info("✓ All detection systems initialized successfully")

    def analyze_url_comprehensive(self, url: str, include_dns_check: bool = True) -> Dict:
        """
        Comprehensive URL analysis with all detection layers

        Args:
            url: URL to analyze
            include_dns_check: Whether to perform DNS checks (slower but more accurate)

        Returns:
            Comprehensive analysis report
        """
        logger.info(f"Starting comprehensive analysis for: {url}")

        analysis_start = datetime.now()

        result = {
            'url': url,
            'timestamp': str(analysis_start),
            'final_verdict': 'UNKNOWN',
            'threat_level': 0,  # 0-100
            'confidence': 0.0,  # 0-1
            'is_phishing': None,
            'layers': {},
            'recommendations': [],
            'risk_factors': [],
            'summary': ''
        }

        try:
            # ============================================
            # LAYER 1: DOMAIN VALIDATION (Critical!)
            # ============================================
            logger.info("Layer 1: Domain validation...")
            if include_dns_check:
                domain_validation = self.domain_validator.validate_url_comprehensive(url)
                result['layers']['domain_validation'] = domain_validation

                # Critical findings from domain validation
                if domain_validation['classification'] == 'INVALID_SYNTAX':
                    result['final_verdict'] = 'INVALID_URL'
                    result['threat_level'] = 0
                    result['confidence'] = 1.0
                    result['is_phishing'] = False
                    result['summary'] = 'Invalid URL syntax - cannot be accessed'
                    result['recommendations'].append('This is not a valid URL format')
                    return result

                elif domain_validation['classification'] == 'RANDOM_GARBAGE_NOT_ON_INTERNET':
                    result['final_verdict'] = 'RANDOM_GARBAGE'
                    result['threat_level'] = 5
                    result['confidence'] = 0.95
                    result['is_phishing'] = False
                    result['summary'] = 'Random gibberish URL that does not exist on internet'
                    result['recommendations'].append(domain_validation['recommendation'])
                    return result

                elif domain_validation['classification'] == 'NOT_ON_INTERNET':
                    # This is CRITICAL - domain doesn't exist but may look like phishing
                    result['risk_factors'].append('🚨 CRITICAL: Domain does NOT exist on the internet')
                    result['threat_level'] = max(result['threat_level'], domain_validation['threat_level'])

                    # Check if it impersonates brands
                    if domain_validation['threat_level'] >= 80:
                        result['final_verdict'] = 'PHISHING_NON_EXISTENT_DOMAIN'
                        result['is_phishing'] = True
                        result['confidence'] = 0.95
                        result['summary'] = '🚨 HIGH THREAT: Impersonates brand but domain does not exist - PHISHING!'
                        result['recommendations'].append(domain_validation['recommendation'])
                        # Continue analysis for more details
            else:
                logger.info("DNS check skipped (fast mode)")

            # ============================================
            # LAYER 2: ULTRA FEATURE EXTRACTION
            # ============================================
            logger.info("Layer 2: Ultra feature extraction...")
            ultra_features = self.ultra_feature_extractor.extract_all_features(url)
            result['layers']['ultra_features'] = {
                'total_features': len(ultra_features),
                'key_features': self._get_key_ultra_features(ultra_features)
            }

            # Analyze ultra features for instant red flags
            ultra_red_flags = self._analyze_ultra_features(ultra_features)
            if ultra_red_flags:
                result['risk_factors'].extend(ultra_red_flags)

            # ============================================
            # LAYER 3: ML MODEL PREDICTION
            # ============================================
            logger.info("Layer 3: ML model prediction...")
            ml_prediction = self.ml_predictor.predict_single_url(url)
            result['layers']['ml_prediction'] = {
                'is_phishing': ml_prediction.get('is_phishing'),
                'confidence': ml_prediction.get('confidence'),
                'detection_method': ml_prediction.get('detection_method'),
                'models_used': len(ml_prediction.get('individual_predictions', {}))
            }

            # ============================================
            # LAYER 4: ADVANCED TYPOSQUATTING DETECTION
            # ============================================
            logger.info("Layer 4: Typosquatting analysis...")
            from urllib.parse import urlparse
            domain = urlparse(url).netloc.replace('www.', '')
            typosquatting_result = self.typosquatting_detector.detect_typosquatting(domain)
            result['layers']['typosquatting_analysis'] = typosquatting_result

            if typosquatting_result['is_typosquatting']:
                severity = typosquatting_result['severity']
                technique = typosquatting_result['technique']
                target = typosquatting_result.get('target_brand', 'unknown')

                if severity == 'critical':
                    result['risk_factors'].append(f'🚨 CRITICAL TYPOSQUATTING: {technique} attack targeting "{target}"')
                    result['threat_level'] = max(result['threat_level'], 85)
                elif severity == 'high':
                    result['risk_factors'].append(f'⚠️ HIGH RISK TYPOSQUATTING: {technique} attack targeting "{target}"')
                    result['threat_level'] = max(result['threat_level'], 70)
                else:
                    result['risk_factors'].append(f'⚠️ TYPOSQUATTING DETECTED: {technique} attack targeting "{target}"')
                    result['threat_level'] = max(result['threat_level'], 55)

            # ============================================
            # LAYER 5: ENHANCED PATTERN DETECTION
            # ============================================
            logger.info("Layer 5: Pattern analysis...")
            pattern_analysis = self.pattern_detector.analyze_url(url)
            result['layers']['pattern_analysis'] = pattern_analysis

            if pattern_analysis['is_suspicious']:
                result['risk_factors'].extend(pattern_analysis['reasons'])

            # ============================================
            # LAYER 5.5: LOCAL PHISHING DATABASE CHECK (No API)
            # ============================================
            phishing_db_result = None
            if self.phishing_db:
                logger.info("Layer 5.5: Checking local phishing database...")
                phishing_db_result = self.phishing_db.check_url(url)
                result['layers']['phishing_database'] = {
                    'risk_score': phishing_db_result['risk_score'],
                    'is_phishing': phishing_db_result['is_phishing'],
                    'confidence': phishing_db_result['confidence'],
                    'detection_method': phishing_db_result['detection_method'],
                    'brand_impersonation': phishing_db_result.get('brand_impersonation'),
                    'matched_patterns': len(phishing_db_result.get('matched_patterns', [])),
                }

                if phishing_db_result['is_phishing']:
                    result['risk_factors'].append(f"🚨 PHISHING DATABASE: High risk score ({phishing_db_result['risk_score']}/100)")
                    for reason in phishing_db_result['reasons'][:3]:
                        result['risk_factors'].append(f"   → {reason}")
                elif phishing_db_result['is_phishing'] is None:
                    result['risk_factors'].append(f"⚠️ SUSPICIOUS: Phishing database flagged ({phishing_db_result['risk_score']}/100)")

            # ============================================
            # LAYER 5.6: PHISHTANK REAL-TIME CHECK (No API Key Required)
            # ============================================
            phishtank_result = None
            if self.phishtank_checker and include_dns_check:  # Only check if DNS checks enabled (slower mode)
                logger.info("Layer 5.6: Checking PhishTank database (real-time)...")
                try:
                    phishtank_result = self.phishtank_checker.check_url(url)
                    result['layers']['phishtank'] = {
                        'in_database': phishtank_result['in_database'],
                        'is_phishing': phishtank_result['is_phishing'],
                        'verified': phishtank_result['verified'],
                        'phish_id': phishtank_result['phish_id'],
                        'cached': phishtank_result['cached'],
                    }

                    if phishtank_result['is_phishing']:
                        result['risk_factors'].append(f"🚨 PHISHTANK CONFIRMED: This URL is in PhishTank database!")
                        if phishtank_result['phish_id']:
                            result['risk_factors'].append(f"   → PhishTank ID: {phishtank_result['phish_id']}")
                    elif phishtank_result['in_database']:
                        result['risk_factors'].append(f"⚠️ URL found in PhishTank (pending verification)")
                except Exception as e:
                    logger.warning(f"PhishTank check failed: {e}")
                    result['layers']['phishtank'] = {'error': str(e)}

            # ============================================
            # LAYER 5.7: GOOGLE SAFE BROWSING (Most Trusted)
            # ============================================
            google_result = None
            if include_dns_check and self.google_checker.api_key:
                logger.info("Layer 5.7: Checking Google Safe Browsing...")
                google_result = self.google_checker.check_url(url)
                result['layers']['google_safe_browsing'] = google_result

                if google_result.get('is_threat'):
                    threat_type = google_result.get('threat_type', 'UNKNOWN')
                    result['risk_factors'].append(f"🚨 GOOGLE SAFE BROWSING: {threat_type} detected!")

            # ============================================
            # LAYER 5.8: VIRUSTOTAL (70+ Scanners)
            # ============================================
            virustotal_result = None
            if include_dns_check and self.virustotal_checker.api_key:
                logger.info("Layer 5.8: Checking VirusTotal (70+ scanners)...")
                virustotal_result = self.virustotal_checker.check_url(url)
                result['layers']['virustotal'] = virustotal_result

                malicious = virustotal_result.get('malicious_count', 0)
                suspicious = virustotal_result.get('suspicious_count', 0)
                if malicious > 0:
                    result['risk_factors'].append(f"🚨 VIRUSTOTAL: {malicious} scanners flagged as MALICIOUS!")
                elif suspicious > 0:
                    result['risk_factors'].append(f"⚠️ VIRUSTOTAL: {suspicious} scanners flagged as suspicious")

            # ============================================
            # LAYER 5.9: URLSCAN.IO (Sandbox Analysis)
            # ============================================
            urlscan_result = None
            if include_dns_check and self.urlscan_checker.api_key:
                logger.info("Layer 5.9: Checking urlscan.io...")
                urlscan_result = self.urlscan_checker.check_url(url)
                result['layers']['urlscan'] = urlscan_result

                if urlscan_result.get('is_malicious'):
                    result['risk_factors'].append(f"🚨 URLSCAN.IO: Malicious verdict!")

            # ============================================
            # LAYER 6: INTELLIGENT THREAT SCORING
            # ============================================
            logger.info("Layer 6: Computing final threat score...")
            final_analysis = self._compute_final_verdict(
                domain_validation=result['layers'].get('domain_validation'),
                ultra_features=ultra_features,
                ml_prediction=ml_prediction,
                pattern_analysis=pattern_analysis,
                typosquatting_result=typosquatting_result,
                phishing_db_result=phishing_db_result,
                phishtank_result=phishtank_result,
                google_result=google_result,
                virustotal_result=virustotal_result,
                urlscan_result=urlscan_result
            )

            result.update(final_analysis)

            # ============================================
            # LAYER 7: GENERATE RECOMMENDATIONS
            # ============================================
            recommendations = self._generate_recommendations(result)
            result['recommendations'].extend(recommendations)

            # Analysis time
            analysis_time = (datetime.now() - analysis_start).total_seconds()
            result['analysis_time_seconds'] = analysis_time

            logger.info(f"Analysis complete in {analysis_time:.2f}s - Verdict: {result['final_verdict']}")

        except Exception as e:
            logger.error(f"Error during analysis: {e}", exc_info=True)
            result['error'] = str(e)
            result['final_verdict'] = 'ERROR'
            result['summary'] = f'Analysis error: {str(e)}'

        return result

    def _get_key_ultra_features(self, ultra_features: Dict) -> Dict:
        """Extract key ultra features for reporting"""
        key_features = {}

        # Typosquatting
        if ultra_features.get('ultra_typosquat_very_close', 0) == 1:
            key_features['typosquatting'] = 'DETECTED'

        # Behavioral indicators
        if ultra_features.get('ultra_suspicious_behavior_score', 0) >= 3:
            key_features['suspicious_behavior'] = 'HIGH'

        # Obfuscation
        if ultra_features.get('ultra_excessive_encoding', 0) == 1:
            key_features['obfuscation'] = 'DETECTED'

        # Brand impersonation
        if ultra_features.get('ultra_brand_keyword_combo', 0) == 1:
            key_features['brand_impersonation'] = 'LIKELY'

        return key_features

    def _analyze_ultra_features(self, ultra_features: Dict) -> List[str]:
        """Analyze ultra features for instant red flags"""
        red_flags = []

        # Typosquatting detection
        if ultra_features.get('ultra_typosquat_very_close', 0) == 1:
            brand_distance = ultra_features.get('ultra_typosquat_min_distance', 999)
            red_flags.append(f'⚠️ TYPOSQUATTING: Domain is {brand_distance} characters different from major brand')

        # Suspicious behavior
        behavior_score = ultra_features.get('ultra_suspicious_behavior_score', 0)
        if behavior_score >= 4:
            red_flags.append(f'🚨 CRITICAL: High suspicious behavior score ({behavior_score}/5)')
        elif behavior_score >= 3:
            red_flags.append(f'⚠️ WARNING: Suspicious behavioral patterns detected ({behavior_score}/5)')

        # Obfuscation
        if ultra_features.get('ultra_excessive_encoding', 0) == 1:
            red_flags.append('⚠️ URL uses excessive encoding - possible obfuscation')

        if ultra_features.get('ultra_suspicious_redirect', 0) == 1:
            red_flags.append('🚨 CRITICAL: Suspicious redirect to external URL')

        # Brand + Action combination
        if ultra_features.get('ultra_brand_plus_action', 0) == 1:
            red_flags.append('⚠️ Brand name combined with action words (common phishing)')

        # Sensitive + Urgency
        if ultra_features.get('ultra_action_plus_urgency', 0) == 1:
            red_flags.append('🚨 Action words combined with urgency - HIGH PHISHING RISK')

        # Data harvesting indicators
        if ultra_features.get('ultra_data_harvest', 0) == 1:
            red_flags.append('⚠️ URL appears designed to harvest personal data')

        # Fake HTTPS
        if ultra_features.get('ultra_secure_in_http_url', 0) == 1:
            red_flags.append('🚨 CRITICAL: Uses "secure" in URL but NOT using HTTPS protocol')

        # Account threat
        if ultra_features.get('ultra_account_threat', 0) == 1:
            red_flags.append('⚠️ Contains account threat language (suspend/lock/close)')

        return red_flags

    def _compute_final_verdict(self, domain_validation: Dict, ultra_features: Dict,
                                ml_prediction: Dict, pattern_analysis: Dict,
                                typosquatting_result: Dict = None,
                                phishing_db_result: Dict = None,
                                phishtank_result: Dict = None,
                                google_result: Dict = None,
                                virustotal_result: Dict = None,
                                urlscan_result: Dict = None) -> Dict:
        """
        Compute final verdict using ALL intelligence sources
        Uses weighted voting and confidence scoring
        """
        verdict = {
            'final_verdict': 'UNKNOWN',
            'threat_level': 0,
            'confidence': 0.0,
            'is_phishing': None,
            'summary': '',
            'reasoning': []
        }

        # Initialize scores
        phishing_score = 0.0
        confidence_scores = []

        # ============================================
        # Weight: Domain Validation (25% weight)
        # ============================================
        if domain_validation:
            classification = domain_validation.get('classification', '')

            if classification == 'NOT_ON_INTERNET':
                if domain_validation.get('threat_level', 0) >= 80:
                    # Likely phishing (impersonates brand but doesn't exist)
                    phishing_score += 25
                    confidence_scores.append(0.95)
                    verdict['reasoning'].append('Domain impersonates brand but does not exist')
                else:
                    phishing_score += 12
                    confidence_scores.append(0.70)
                    verdict['reasoning'].append('Domain does not exist on internet')

            elif classification == 'EXISTS_BUT_SUSPICIOUS':
                phishing_score += 18
                confidence_scores.append(0.75)
                verdict['reasoning'].append('Domain exists but appears suspicious')

            elif classification == 'REAL_DOMAIN_EXISTS':
                # Domain is real - reduce baseline suspicion
                phishing_score += 0
                confidence_scores.append(0.85)
                verdict['reasoning'].append('Domain exists on internet (verified via DNS)')

        # ============================================
        # Weight: TYPOSQUATTING DETECTION (20% weight) - NEW!
        # ============================================
        if typosquatting_result and typosquatting_result.get('is_typosquatting'):
            severity = typosquatting_result.get('severity', 'medium')
            confidence = typosquatting_result.get('confidence', 0.5)
            technique = typosquatting_result.get('technique', 'unknown')
            target = typosquatting_result.get('target_brand', 'brand')

            if severity == 'critical':
                # IDN homograph or exact match - extremely dangerous
                phishing_score += 20
                confidence_scores.append(0.95)
                verdict['reasoning'].append(f'CRITICAL: {technique} attack targeting {target} (confidence: {confidence:.0%})')
            elif severity == 'high':
                # Very close typosquat (1-2 char difference)
                phishing_score += 16
                confidence_scores.append(0.90)
                verdict['reasoning'].append(f'HIGH RISK: {technique} targeting {target} (confidence: {confidence:.0%})')
            else:  # medium
                phishing_score += 10
                confidence_scores.append(0.80)
                verdict['reasoning'].append(f'Typosquatting detected: {technique} targeting {target}')

        # ============================================
        # Weight: ML Prediction (25% weight)
        # ============================================
        if ml_prediction:
            is_phishing_ml = ml_prediction.get('is_phishing', 0)
            ml_confidence = ml_prediction.get('confidence', 0.5)

            if is_phishing_ml == 1:
                phishing_score += 25
                confidence_scores.append(ml_confidence)
                verdict['reasoning'].append(f'ML models predict phishing (confidence: {ml_confidence:.2%})')
            else:
                phishing_score += 0
                confidence_scores.append(ml_confidence)
                verdict['reasoning'].append(f'ML models predict legitimate (confidence: {ml_confidence:.2%})')

        # ============================================
        # Weight: Pattern Analysis (20% weight)
        # ============================================
        if pattern_analysis:
            pattern_risk = pattern_analysis.get('risk_score', 0)

            if pattern_risk >= 50:
                phishing_score += 20
                confidence_scores.append(0.90)
                verdict['reasoning'].append(f'Extremely suspicious patterns detected (risk: {pattern_risk}/100)')
            elif pattern_risk >= 30:
                phishing_score += 16
                confidence_scores.append(0.80)
                verdict['reasoning'].append(f'Highly suspicious patterns detected (risk: {pattern_risk}/100)')
            elif pattern_risk >= 15:
                phishing_score += 8
                confidence_scores.append(0.70)
                verdict['reasoning'].append(f'Suspicious patterns detected (risk: {pattern_risk}/100)')

        # ============================================
        # Weight: Ultra Features (10% weight)
        # ============================================
        behavior_score = ultra_features.get('ultra_suspicious_behavior_score', 0)
        typosquat_score = ultra_features.get('ultra_typosquat_very_close', 0)

        if behavior_score >= 4 or typosquat_score == 1:
            phishing_score += 10
            confidence_scores.append(0.85)
            verdict['reasoning'].append('Advanced heuristics indicate high phishing risk')
        elif behavior_score >= 3:
            phishing_score += 6
            confidence_scores.append(0.75)

        # ============================================
        # Weight: Local Phishing Database (15% weight) - NEW!
        # ============================================
        if phishing_db_result:
            db_risk = phishing_db_result.get('risk_score', 0)
            db_is_phishing = phishing_db_result.get('is_phishing')

            if db_is_phishing is True:
                phishing_score += 15
                confidence_scores.append(phishing_db_result.get('confidence', 0.8))
                verdict['reasoning'].append(f'Local phishing database: HIGH RISK ({db_risk}/100)')
            elif db_is_phishing is None:  # Suspicious
                phishing_score += 8
                confidence_scores.append(0.7)
                verdict['reasoning'].append(f'Local phishing database: SUSPICIOUS ({db_risk}/100)')
            elif db_risk >= 20:
                phishing_score += 4
                confidence_scores.append(0.6)
                verdict['reasoning'].append(f'Local phishing database: Minor flags ({db_risk}/100)')

        # ============================================
        # Weight: PhishTank Database (15% weight)
        # ============================================
        if phishtank_result and not phishtank_result.get('error'):
            if phishtank_result.get('is_phishing'):
                phishing_score += 15
                confidence_scores.append(0.95)
                verdict['reasoning'].append('PhishTank CONFIRMED: URL is verified phishing!')
            elif phishtank_result.get('in_database'):
                phishing_score += 10
                confidence_scores.append(0.85)
                verdict['reasoning'].append('PhishTank: URL found in database (pending verification)')

        # ============================================
        # Weight: Google Safe Browsing (25% weight) - HIGHEST TRUST
        # ============================================
        if google_result and google_result.get('checked'):
            if google_result.get('is_threat'):
                # Google Safe Browsing is extremely reliable
                phishing_score += 25
                confidence_scores.append(0.99)
                threat_type = google_result.get('threat_type', 'THREAT')
                verdict['reasoning'].append(f'Google Safe Browsing: {threat_type} CONFIRMED!')
            elif not google_result.get('error'):
                # Google checked and found nothing - slight boost to confidence
                confidence_scores.append(0.90)
                verdict['reasoning'].append('Google Safe Browsing: No threats found')

        # ============================================
        # Weight: VirusTotal (20% weight) - 70+ Scanners
        # ============================================
        if virustotal_result and virustotal_result.get('checked'):
            malicious = virustotal_result.get('malicious_count', 0)
            suspicious = virustotal_result.get('suspicious_count', 0)

            if malicious >= 5:
                phishing_score += 20
                confidence_scores.append(0.98)
                verdict['reasoning'].append(f'VirusTotal: {malicious} scanners flagged MALICIOUS!')
            elif malicious >= 2:
                phishing_score += 15
                confidence_scores.append(0.92)
                verdict['reasoning'].append(f'VirusTotal: {malicious} scanners flagged malicious')
            elif malicious >= 1 or suspicious >= 3:
                phishing_score += 10
                confidence_scores.append(0.85)
                verdict['reasoning'].append(f'VirusTotal: Some scanners flagged this URL')
            elif not virustotal_result.get('error') and not virustotal_result.get('not_found'):
                confidence_scores.append(0.88)
                verdict['reasoning'].append('VirusTotal: Clean (70+ scanners)')

        # ============================================
        # Weight: urlscan.io (10% weight) - Sandbox Analysis
        # ============================================
        if urlscan_result and urlscan_result.get('checked'):
            if urlscan_result.get('is_malicious'):
                phishing_score += 10
                confidence_scores.append(0.90)
                verdict['reasoning'].append('urlscan.io: Malicious verdict')
            elif urlscan_result.get('score', 0) >= 50:
                phishing_score += 5
                confidence_scores.append(0.80)
                verdict['reasoning'].append(f"urlscan.io: High risk score ({urlscan_result['score']})")

        # ============================================
        # FINAL COMPUTATION
        # ============================================
        verdict['threat_level'] = min(int(phishing_score), 100)

        # Determine if phishing
        if phishing_score >= 60:
            verdict['is_phishing'] = True
            verdict['final_verdict'] = 'PHISHING_DETECTED'
            verdict['summary'] = '🚨 HIGH CONFIDENCE PHISHING DETECTED - DO NOT VISIT!'
        elif phishing_score >= 40:
            verdict['is_phishing'] = True
            verdict['final_verdict'] = 'LIKELY_PHISHING'
            verdict['summary'] = '⚠️ LIKELY PHISHING - Strong indicators of malicious intent'
        elif phishing_score >= 25:
            verdict['is_phishing'] = True
            verdict['final_verdict'] = 'SUSPICIOUS'
            verdict['summary'] = '⚠️ SUSPICIOUS - Multiple phishing indicators detected'
        elif phishing_score >= 15:
            verdict['is_phishing'] = None  # Unclear
            verdict['final_verdict'] = 'QUESTIONABLE'
            verdict['summary'] = '⚡ QUESTIONABLE - Some suspicious elements, proceed with caution'
        else:
            verdict['is_phishing'] = False
            verdict['final_verdict'] = 'APPEARS_SAFE'
            verdict['summary'] = '✓ APPEARS SAFE - No significant threats detected'

        # Compute average confidence
        verdict['confidence'] = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.5

        return verdict

    def _generate_recommendations(self, result: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []

        verdict = result.get('final_verdict', '')
        threat_level = result.get('threat_level', 0)

        if verdict == 'PHISHING_DETECTED':
            recommendations.append('🛑 DO NOT visit this website')
            recommendations.append('🛑 DO NOT enter any personal information')
            recommendations.append('🛑 DO NOT download any files')
            recommendations.append('📧 Report this URL to authorities if received via email')
            recommendations.append('🔒 Run antivirus scan if you already visited')

        elif verdict == 'LIKELY_PHISHING':
            recommendations.append('⚠️ Strongly advised NOT to visit')
            recommendations.append('⚠️ Do not enter passwords or sensitive data')
            recommendations.append('🔍 Verify legitimacy through official channels')
            recommendations.append('📧 Contact the organization directly if this claims to be from them')

        elif verdict == 'SUSPICIOUS':
            recommendations.append('⚠️ Exercise extreme caution')
            recommendations.append('🔍 Verify the URL matches the official website')
            recommendations.append('📧 Check if this matches links from official sources')
            recommendations.append('🔒 Ensure HTTPS is used before entering any data')

        elif verdict == 'QUESTIONABLE':
            recommendations.append('⚡ Proceed with caution')
            recommendations.append('🔍 Double-check the domain name for typos')
            recommendations.append('🔒 Only proceed if you trust the source')

        else:  # APPEARS_SAFE
            recommendations.append('✓ URL appears legitimate')
            recommendations.append('🔒 Still verify HTTPS for sensitive transactions')
            recommendations.append('📋 Be cautious of unexpected links, even from safe domains')

        # Additional recommendations based on specific findings
        domain_val = result['layers'].get('domain_validation', {})
        if domain_val.get('classification') == 'NOT_ON_INTERNET':
            recommendations.append('⚠️ This domain does not exist - cannot access even if you try')

        return recommendations

    def analyze_batch(self, urls: List[str], include_dns_check: bool = False) -> List[Dict]:
        """Analyze multiple URLs"""
        logger.info(f"Starting batch analysis of {len(urls)} URLs")

        results = []
        for i, url in enumerate(urls, 1):
            logger.info(f"Analyzing URL {i}/{len(urls)}")
            result = self.analyze_url_comprehensive(url, include_dns_check=include_dns_check)
            results.append(result)

        return results

    def generate_report(self, analysis: Dict) -> str:
        """Generate human-readable report"""
        report = []
        report.append("=" * 80)
        report.append("ULTIMATE PHISHING DETECTION REPORT")
        report.append("=" * 80)
        report.append(f"\nURL: {analysis['url']}")
        report.append(f"Timestamp: {analysis['timestamp']}")
        report.append(f"Analysis Time: {analysis.get('analysis_time_seconds', 0):.2f} seconds")
        report.append("\n" + "-" * 80)
        report.append("FINAL VERDICT")
        report.append("-" * 80)
        report.append(f"Verdict: {analysis['final_verdict']}")
        report.append(f"Threat Level: {analysis['threat_level']}/100")
        report.append(f"Confidence: {analysis['confidence']:.2%}")
        report.append(f"\n{analysis['summary']}")

        if analysis.get('reasoning'):
            report.append("\n" + "-" * 80)
            report.append("REASONING")
            report.append("-" * 80)
            for reason in analysis['reasoning']:
                report.append(f"• {reason}")

        if analysis.get('risk_factors'):
            report.append("\n" + "-" * 80)
            report.append("RISK FACTORS")
            report.append("-" * 80)
            for factor in analysis['risk_factors'][:10]:  # Top 10
                report.append(f"• {factor}")

        if analysis.get('recommendations'):
            report.append("\n" + "-" * 80)
            report.append("RECOMMENDATIONS")
            report.append("-" * 80)
            for rec in analysis['recommendations']:
                report.append(f"• {rec}")

        # Layer summaries
        if 'layers' in analysis:
            report.append("\n" + "-" * 80)
            report.append("DETECTION LAYERS")
            report.append("-" * 80)

            if 'domain_validation' in analysis['layers']:
                dv = analysis['layers']['domain_validation']
                report.append(f"\nLayer 1: Domain Validation")
                report.append(f"  Classification: {dv.get('classification', 'N/A')}")
                report.append(f"  On Internet: {dv.get('is_on_internet', False)}")
                report.append(f"  Syntax Valid: {dv.get('is_valid_syntax', False)}")

            if 'ml_prediction' in analysis['layers']:
                ml = analysis['layers']['ml_prediction']
                report.append(f"\nLayer 2: ML Prediction")
                report.append(f"  Phishing: {ml.get('is_phishing', 'N/A')}")
                report.append(f"  Confidence: {ml.get('confidence', 0):.2%}")
                report.append(f"  Models Used: {ml.get('models_used', 0)}")

            if 'pattern_analysis' in analysis['layers']:
                pa = analysis['layers']['pattern_analysis']
                report.append(f"\nLayer 3: Pattern Analysis")
                report.append(f"  Risk Score: {pa.get('risk_score', 0)}/100")
                report.append(f"  Suspicious: {pa.get('is_suspicious', False)}")

        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)

        return "\n".join(report)


if __name__ == '__main__':
    # Test the ultimate predictor
    predictor = UltimatePhishingPredictor()

    test_urls = [
        'https://www.google.com',
        'http://secure-paypal-verify.tk/login',
        'https://gooogle.com',  # Typosquatting
        'http://randomgarbage12345xyz.ml',  # Random domain
        'https://thisdoesnotexist123456789.com',  # Non-existent
    ]

    print("\n" + "=" * 80)
    print("ULTIMATE PHISHING PREDICTOR TEST")
    print("=" * 80)

    for url in test_urls:
        print(f"\n{'='*80}")
        print(f"Testing: {url}")
        print('='*80)

        result = predictor.analyze_url_comprehensive(url, include_dns_check=True)

        print(f"\nVerdict: {result['final_verdict']}")
        print(f"Threat Level: {result['threat_level']}/100")
        print(f"Confidence: {result['confidence']:.1%}")
        print(f"\nSummary: {result['summary']}")

        if result.get('risk_factors'):
            print(f"\nTop Risk Factors:")
            for factor in result['risk_factors'][:3]:
                print(f"  • {factor}")

        print("\n" + "-" * 80)
