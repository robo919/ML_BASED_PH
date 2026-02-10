"""
Predictor Module for ML Phishing URL Detection System
Handles real-time URL prediction using trained models
"""

import pandas as pd
import numpy as np
import joblib
import os
import logging
import requests
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse
from feature_extractor import FeatureExtractor
from enhanced_pattern_detector import EnhancedPatternDetector

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PhishingPredictor:
    """
    Phishing URL predictor using trained models
    Provides real-time predictions with confidence scores
    """

    def __init__(self, models_dir: str = 'models'):
        """Initialize predictor with trained models"""
        self.models_dir = models_dir
        self.models = {}
        self.scaler = None
        self.feature_names = None
        self.feature_extractor = FeatureExtractor()
        self.pattern_detector = EnhancedPatternDetector()

        self.load_models()

    def load_models(self):
        """Load all trained models from disk"""
        logger.info("Loading trained models...")

        # Load models
        model_files = {
            'random_forest': 'random_forest_model.pkl',
            'xgboost': 'xgboost_model.pkl',
            'logistic_regression': 'logistic_regression_model.pkl',
            'decision_tree': 'decision_tree_model.pkl',
            'svm': 'svm_model.pkl',
            'neural_network': 'neural_network_model.pkl',
            'lightgbm': 'lightgbm_model.pkl',
            'ensemble': 'ensemble_model.pkl'
        }

        for name, filename in model_files.items():
            path = os.path.join(self.models_dir, filename)
            if os.path.exists(path):
                try:
                    self.models[name] = joblib.load(path)
                    logger.info(f"Loaded {name}")
                except Exception as e:
                    logger.error(f"Error loading {name}: {e}")

        # Load scaler
        scaler_path = os.path.join(self.models_dir, 'feature_scaler.pkl')
        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
            logger.info("Loaded feature scaler")

        # Load feature names
        feature_names_path = os.path.join(self.models_dir, 'feature_names.pkl')
        if os.path.exists(feature_names_path):
            self.feature_names = joblib.load(feature_names_path)
            logger.info(f"Loaded {len(self.feature_names)} feature names")

        if not self.models:
            logger.error("No models loaded! Please train models first.")
        else:
            logger.info(f"Successfully loaded {len(self.models)} models")

    def validate_url(self, url: str) -> Tuple[bool, str]:
        """
        Validate URL format

        Args:
            url: URL string to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not url or not isinstance(url, str):
            return False, "URL must be a non-empty string"

        # Basic URL validation
        url = url.strip()

        if not url:
            return False, "URL cannot be empty"

        # Check if URL has a scheme
        if not url.startswith(('http://', 'https://')):
            # Try adding http://
            url = 'http://' + url

        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return False, "Invalid URL format: missing domain"
            return True, url
        except Exception as e:
            return False, f"Invalid URL format: {str(e)}"

    def check_url_availability(self, url: str, timeout: int = 5) -> Dict[str, any]:
        """
        Check if URL is accessible/active

        Args:
            url: URL to check
            timeout: Request timeout in seconds

        Returns:
            Dictionary with availability status
        """
        result = {
            'is_available': False,
            'status_code': None,
            'error': None,
            'response_time': None
        }

        try:
            import time
            start_time = time.time()

            # Make HEAD request (faster than GET)
            response = requests.head(url, timeout=timeout, allow_redirects=True,
                                   headers={'User-Agent': 'Mozilla/5.0'})

            result['response_time'] = time.time() - start_time
            result['status_code'] = response.status_code

            # Consider 2xx and 3xx as available
            if 200 <= response.status_code < 400:
                result['is_available'] = True
            elif response.status_code == 405:  # Method not allowed, try GET
                response = requests.get(url, timeout=timeout, allow_redirects=True,
                                      headers={'User-Agent': 'Mozilla/5.0'}, stream=True)
                result['status_code'] = response.status_code
                if 200 <= response.status_code < 400:
                    result['is_available'] = True

        except requests.exceptions.Timeout:
            result['error'] = 'timeout'
        except requests.exceptions.ConnectionError:
            result['error'] = 'connection_failed'
        except requests.exceptions.TooManyRedirects:
            result['error'] = 'too_many_redirects'
        except requests.exceptions.SSLError:
            result['error'] = 'ssl_error'
        except Exception as e:
            result['error'] = str(e)

        return result

    def predict_single_url(self, url: str) -> Dict:
        """
        Predict whether a single URL is phishing or legitimate

        Args:
            url: URL string to analyze

        Returns:
            Dictionary with prediction results
        """
        # Validate URL
        is_valid, result = self.validate_url(url)
        if not is_valid:
            return {
                'url': url,
                'error': result,
                'is_phishing': None,
                'confidence': 0.0
            }

        url = result  # Use validated/corrected URL

        # Extract features
        try:
            features = self.feature_extractor.extract_all_features(url)
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return {
                'url': url,
                'error': f"Feature extraction error: {str(e)}",
                'is_phishing': None,
                'confidence': 0.0
            }

        # Convert features to DataFrame
        features_df = pd.DataFrame([features])

        # Ensure all expected features are present
        if self.feature_names:
            for feat in self.feature_names:
                if feat not in features_df.columns:
                    features_df[feat] = 0

            # Reorder columns to match training
            features_df = features_df[self.feature_names]

        # Scale features
        if self.scaler:
            features_scaled = self.scaler.transform(features_df)
            features_df = pd.DataFrame(features_scaled, columns=self.feature_names)

        # Get predictions from all models
        predictions = {}
        probabilities = {}

        # Convert DataFrame to numpy for XGBoost compatibility
        features_array = features_df.values if hasattr(features_df, 'values') else features_df

        for model_name, model in self.models.items():
            try:
                # Use array for XGBoost and ensemble (which contains XGBoost), DataFrame for others
                if 'xgboost' in model_name.lower() or 'xgb' in model_name.lower() or 'ensemble' in model_name.lower():
                    pred = model.predict(features_array)[0]
                    if hasattr(model, 'predict_proba'):
                        proba = model.predict_proba(features_array)[0]
                        probabilities[model_name] = proba[1]
                else:
                    pred = model.predict(features_df)[0]
                    if hasattr(model, 'predict_proba'):
                        proba = model.predict_proba(features_df)[0]
                        probabilities[model_name] = proba[1]
                    else:
                        probabilities[model_name] = float(pred)

                predictions[model_name] = pred

            except Exception as e:
                logger.error(f"Error predicting with {model_name}: {e}")

        # Ensemble vote
        if predictions:
            phishing_votes = sum(predictions.values())
            total_votes = len(predictions)
            ensemble_prediction = 1 if phishing_votes > total_votes / 2 else 0
            ensemble_confidence = max(probabilities.values()) if probabilities else 0.5
        else:
            ensemble_prediction = None
            ensemble_confidence = 0.0

        # Analyze risk factors
        risk_factors = self._analyze_risk_factors(url, features)

        # Enhanced pattern-based detection (catches obvious phishing ML might miss)
        pattern_analysis = self.pattern_detector.analyze_url(url)

        # Override ML prediction if pattern detector has high confidence
        final_prediction = ensemble_prediction
        final_confidence = ensemble_confidence
        detection_method = 'ml_ensemble'

        if pattern_analysis['is_suspicious']:
            # Pattern detector found obvious phishing indicators
            if pattern_analysis['risk_score'] >= 30:
                # High risk - override ML model
                final_prediction = 1  # Phishing
                final_confidence = pattern_analysis['confidence']
                detection_method = 'pattern_override'

                # Add pattern-based risk factors
                for reason in pattern_analysis['reasons']:
                    if reason not in risk_factors:
                        risk_factors.insert(0, f"[PATTERN] {reason}")

        # If ML says safe but pattern detector says questionable, boost confidence check
        elif ensemble_prediction == 0 and pattern_analysis['risk_score'] >= 15:
            # Medium risk - flag for review
            risk_factors.insert(0, f"[WARNING] Pattern analysis detected suspicious indicators (score: {pattern_analysis['risk_score']})")

        # Check URL availability (optional - can be slow)
        availability = None
        availability_status = None

        # Only check availability if pattern detector found suspicious indicators
        if pattern_analysis['risk_score'] >= 15:
            availability = self.check_url_availability(url, timeout=3)

            if not availability['is_available']:
                if availability['error'] in ['connection_failed', 'timeout']:
                    # URL is not accessible
                    if pattern_analysis['is_suspicious']:
                        # Suspicious pattern + inactive = likely old phishing site
                        availability_status = "inactive_suspicious"
                        risk_factors.insert(0, "[WARNING] URL is currently inactive but matches phishing patterns - likely a previous phishing attempt")
                    else:
                        availability_status = "inactive_unknown"
                        risk_factors.insert(0, "[INFO] URL is currently inactive or unreachable")
                elif availability['error'] == 'ssl_error':
                    availability_status = "ssl_error"
                    risk_factors.insert(0, "[WARNING] SSL certificate error - potential security risk")

        # Build result
        result = {
            'url': url,
            'is_phishing': final_prediction,
            'confidence': final_confidence,
            'detection_method': detection_method,
            'availability': availability,
            'availability_status': availability_status,
            'pattern_analysis': pattern_analysis,
            'individual_predictions': predictions,
            'individual_probabilities': probabilities,
            'features': features,
            'risk_factors': risk_factors,
            'error': None
        }

        return result

    def predict_batch(self, urls: List[str]) -> List[Dict]:
        """
        Predict multiple URLs

        Args:
            urls: List of URL strings

        Returns:
            List of prediction results
        """
        logger.info(f"Predicting {len(urls)} URLs...")

        results = []
        for url in urls:
            result = self.predict_single_url(url)
            results.append(result)

        return results

    def _analyze_risk_factors(self, url: str, features: Dict) -> List[str]:
        """
        Analyze and list risk factors found in URL

        Args:
            url: URL string
            features: Extracted features dictionary

        Returns:
            List of risk factor descriptions
        """
        risk_factors = []

        # Check suspicious TLD
        if features.get('is_suspicious_tld', 0) == 1:
            parsed = urlparse(url)
            domain_parts = parsed.netloc.split('.')
            if len(domain_parts) >= 2:
                tld = '.' + domain_parts[-1]
                risk_factors.append(f"Suspicious TLD ({tld}) commonly used in phishing")

        # Check IP address
        if features.get('has_ip_address', 0) == 1:
            risk_factors.append("URL contains IP address instead of domain name")

        # Check @ symbol
        if features.get('has_at_symbol', 0) == 1:
            risk_factors.append("URL contains @ symbol (potential URL obfuscation)")

        # Check suspicious keywords
        keyword_count = features.get('suspicious_keyword_count', 0)
        if keyword_count > 0:
            risk_factors.append(f"Contains {keyword_count} suspicious keyword(s) (login, verify, secure, etc.)")

        # Check brand name with suspicious TLD
        if features.get('brand_with_suspicious_tld', 0) == 1:
            risk_factors.append("Brand name combined with suspicious TLD (common phishing pattern)")

        # Check URL length
        if features.get('url_length', 0) > 75:
            risk_factors.append("Unusually long URL (may indicate obfuscation)")

        # Check excessive subdomains
        if features.get('subdomain_count', 0) > 3:
            risk_factors.append(f"Excessive subdomains ({features.get('subdomain_count', 0)})")

        # Check URL shortener
        if features.get('is_url_shortener', 0) == 1:
            risk_factors.append("URL shortener detected (hides actual destination)")

        # Check hexadecimal encoding
        if features.get('has_hex_encoding', 0) == 1:
            risk_factors.append("URL contains hexadecimal encoding (potential obfuscation)")

        # Check HTTPS
        if features.get('is_https', 0) == 0:
            risk_factors.append("Not using HTTPS (insecure connection)")

        # Check high entropy (randomness)
        if features.get('url_entropy', 0) > 4.5:
            risk_factors.append("High randomness in URL (possible generated/random domain)")

        # Check port number
        if features.get('has_port', 0) == 1:
            risk_factors.append("Non-standard port number specified")

        # Check IDN homograph attack
        if features.get('is_idn_homograph', 0) == 1:
            idn_score = features.get('idn_homograph_score', 0.0)
            risk_factors.append(f"[!] IDN HOMOGRAPH ATTACK DETECTED - Mixed script characters found (score: {idn_score:.2f})")

        # Check Unicode characters
        if features.get('has_unicode_chars', 0) == 1:
            risk_factors.append("Contains Unicode/non-ASCII characters (potential homograph attack)")

        # Check mixed scripts
        if features.get('mixed_scripts', 0) == 1:
            risk_factors.append("Mixed character scripts detected (Latin + Cyrillic/Greek)")

        # Check phishing keyword match
        if features.get('phishing_keyword_match', 0) == 1:
            risk_factors.append("[!] KNOWN PHISHING KEYWORD DETECTED - Matches known phishing patterns")

        # Check suspicious pattern match
        if features.get('suspicious_pattern_match', 0) == 1:
            risk_factors.append("[!] SUSPICIOUS URL PATTERN - Matches known phishing URL structure")

        # Check typosquatting
        if features.get('typosquatting_detected', 0) == 1:
            risk_factors.append("[!] TYPOSQUATTING DETECTED - Domain mimics well-known brand")

        # Check suspicious port
        if features.get('suspicious_port', 0) == 1:
            risk_factors.append("Suspicious port number (commonly used in phishing)")

        # Check suspicious extension
        if features.get('suspicious_extension', 0) == 1:
            risk_factors.append("Suspicious file extension detected (executable/script file)")

        # Check known phishing path
        if features.get('known_phishing_path', 0) == 1:
            risk_factors.append("[!] KNOWN PHISHING PATH - Matches database of phishing URL paths")

        # Check brand impersonation
        if features.get('likely_brand_impersonation', 0) == 1:
            brand_score = features.get('brand_impersonation_score', 0.0)
            risk_factors.append(f"[!] BRAND IMPERSONATION DETECTED - Imitating legitimate brand (score: {brand_score:.2f})")

        # Check brand in subdomain
        if features.get('brand_in_subdomain', 0) == 1:
            risk_factors.append("Brand name found in subdomain (common phishing technique)")

        # Check brand with hyphens
        if features.get('brand_with_hyphens', 0) == 1:
            risk_factors.append("Brand name with hyphens detected (typosquatting indicator)")

        return risk_factors

    def get_feature_explanation(self, features: Dict) -> Dict:
        """
        Get human-readable explanations of key features

        Args:
            features: Extracted features dictionary

        Returns:
            Dictionary of feature explanations
        """
        explanations = {}

        # URL structure
        explanations['URL Length'] = f"{features.get('url_length', 0)} characters"
        explanations['Domain Length'] = f"{features.get('domain_length', 0)} characters"

        # Protocol
        protocol = "HTTPS" if features.get('is_https', 0) == 1 else "HTTP"
        explanations['Protocol'] = protocol

        # TLD
        tld_suspicious = "Suspicious" if features.get('is_suspicious_tld', 0) == 1 else "Normal"
        explanations['TLD Type'] = tld_suspicious

        # Subdomains
        explanations['Subdomain Count'] = features.get('subdomain_count', 0)

        # Special characters
        explanations['Dots'] = features.get('dot_count', 0)
        explanations['Hyphens'] = features.get('hyphen_count', 0)
        explanations['Underscores'] = features.get('underscore_count', 0)

        # Keywords
        explanations['Suspicious Keywords'] = features.get('suspicious_keyword_count', 0)

        # Entropy
        explanations['URL Entropy'] = f"{features.get('url_entropy', 0):.2f}"

        # IP address
        has_ip = "Yes" if features.get('has_ip_address', 0) == 1 else "No"
        explanations['Has IP Address'] = has_ip

        return explanations


if __name__ == '__main__':
    # Test predictor
    predictor = PhishingPredictor()

    test_urls = [
        'https://www.google.com',
        'http://secure-paypal-login.ml/verify'
    ]

    for url in test_urls:
        result = predictor.predict_single_url(url)
        print(f"\nURL: {url}")
        print(f"Prediction: {'PHISHING' if result['is_phishing'] == 1 else 'LEGITIMATE'}")
        print(f"Confidence: {result['confidence']:.2%}")
