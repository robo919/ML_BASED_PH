"""
ML Phishing URL Detector - Main Application
All-in-one detection system with comprehensive menu
"""

import sys
import os
import time
from datetime import datetime

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from colorama import init, Fore, Back, Style
import pandas as pd

# Initialize colorama
init(autoreset=True)


class PhishingDetector:
    """Main detector application"""

    def __init__(self):
        self.predictor = None
        self.models_loaded = False
        self.check_models()

    def check_models(self):
        """Check if models are trained"""
        # Change to parent directory for model access
        parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        models_dir = os.path.join(parent_dir, 'models')

        # Check if any model exists (look for random_forest or ensemble)
        rf_path = os.path.join(models_dir, 'random_forest_model.pkl')
        ensemble_path = os.path.join(models_dir, 'ensemble_model.pkl')

        if os.path.exists(rf_path) or os.path.exists(ensemble_path):
            try:
                # Import predictor module (path already added at top of file)
                from predictor import PhishingPredictor  # type: ignore

                self.predictor = PhishingPredictor(models_dir=models_dir)
                self.models_loaded = True
            except Exception as e:
                print(f"\n{Fore.RED}[ERROR] Failed to load models: {e}{Style.RESET_ALL}")
                import traceback
                traceback.print_exc()
                self.models_loaded = False
        else:
            print(f"\n{Fore.YELLOW}[!] Model files not found at: {models_dir}{Style.RESET_ALL}")
            self.models_loaded = False

    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Fore.CYAN}{'='*70}
{Fore.YELLOW}   ML PHISHING URL DETECTOR v2.0{Fore.CYAN}
{Fore.GREEN}   Advanced AI-Powered URL Security Scanner{Fore.CYAN}
{'='*70}{Style.RESET_ALL}
"""
        print(banner)

        if self.models_loaded:
            print(f"{Fore.GREEN}[+] Models loaded and ready{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Models not trained yet - Select option 1 first{Style.RESET_ALL}")
        print()

    def print_main_menu(self):
        """Print main menu"""
        menu = f"""
{Fore.CYAN}==================== MAIN MENU ===================={Style.RESET_ALL}

  {Fore.CYAN}[ SETUP ]{Style.RESET_ALL}
  {Fore.GREEN}1.{Style.RESET_ALL} Train ML Models (First time only)

  {Fore.CYAN}[ URL DETECTION ]{Style.RESET_ALL}
  {Fore.GREEN}2.{Style.RESET_ALL} Check Single URL
  {Fore.GREEN}3.{Style.RESET_ALL} Batch Check URLs (from file)
  {Fore.GREEN}4.{Style.RESET_ALL} Quick Check (Simple mode)
  {Fore.GREEN}5.{Style.RESET_ALL} Check Multiple URLs (Paste list)

  {Fore.CYAN}[ ANALYSIS & REPORTS ]{Style.RESET_ALL}
  {Fore.GREEN}6.{Style.RESET_ALL} View Model Performance
  {Fore.GREEN}7.{Style.RESET_ALL} Generate Full Report
  {Fore.GREEN}8.{Style.RESET_ALL} View Detection History
  {Fore.GREEN}9.{Style.RESET_ALL} Export Results

  {Fore.CYAN}[ TOOLS ]{Style.RESET_ALL}
  {Fore.GREEN}10.{Style.RESET_ALL} Compare URL Safety
  {Fore.GREEN}11.{Style.RESET_ALL} Test New Features (IDN, Brand, Typosquatting)
  {Fore.GREEN}12.{Style.RESET_ALL} View Visualizations Info

  {Fore.GREEN}0.{Style.RESET_ALL}  Exit

{Fore.CYAN}==================================================={Style.RESET_ALL}

{Fore.YELLOW}Enter your choice (0-12): {Style.RESET_ALL}"""
        return input(menu)

    def train_models(self):
        """Train all ML models"""
        print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Starting Model Training Pipeline{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[Time] This will take 15-30 minutes...{Style.RESET_ALL}\n")

        try:
            # Change to parent directory
            parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            os.chdir(parent_dir)

            # Import and run training
            sys.path.insert(0, os.path.join(parent_dir, 'src'))
            from train_models import main
            main()

            # Reload predictor
            self.check_models()

            print(f"\n{Fore.GREEN}[+] Training complete! Models are ready to use.{Style.RESET_ALL}")

        except Exception as e:
            print(f"\n{Fore.RED}Error during training: {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()

    def check_single_url(self):
        """Check a single URL with detailed analysis"""
        if not self.models_loaded:
            print(f"\n{Fore.RED}[x] Models not loaded. Please train first (option 1).{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}SINGLE URL ANALYSIS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

        url = input(f"{Fore.YELLOW}Enter URL to analyze: {Style.RESET_ALL}").strip()

        if not url:
            print(f"{Fore.RED}Error: URL cannot be empty{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}  Analyzing URL...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

        result = self.predictor.predict_single_url(url)

        if result['error']:
            print(f"{Fore.RED}Error: {result['error']}{Style.RESET_ALL}\n")
            return

        self.display_detailed_result(result)

    def quick_check(self):
        """Quick check without detailed analysis"""
        if not self.models_loaded:
            print(f"\n{Fore.RED}[x] Models not loaded. Please train first (option 1).{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}QUICK CHECK MODE{Style.RESET_ALL}\n")

        url = input(f"{Fore.YELLOW}URL: {Style.RESET_ALL}").strip()

        if not url:
            return

        print(f"{Fore.CYAN}Checking...{Style.RESET_ALL} ", end='', flush=True)

        result = self.predictor.predict_single_url(url)

        if result['error']:
            print(f"{Fore.RED}ERROR{Style.RESET_ALL}")
            return

        if result['is_phishing'] == 1:
            print(f"{Fore.RED}[PHISHING] PHISHING{Style.RESET_ALL} ({result['confidence']*100:.1f}% confidence)")
        else:
            print(f"{Fore.GREEN}[SAFE] SAFE{Style.RESET_ALL} ({result['confidence']*100:.1f}% confidence)")

    def check_multiple_urls(self):
        """Check multiple URLs from paste"""
        if not self.models_loaded:
            print(f"\n{Fore.RED}[x] Models not loaded. Please train first (option 1).{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}MULTIPLE URL CHECK{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Paste URLs (one per line, empty line to finish):{Style.RESET_ALL}\n")

        urls = []
        while True:
            url = input().strip()
            if not url:
                break
            urls.append(url)

        if not urls:
            print(f"{Fore.RED}No URLs entered{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}Analyzing {len(urls)} URLs...{Style.RESET_ALL}\n")

        results = []
        for i, url in enumerate(urls, 1):
            result = self.predictor.predict_single_url(url)
            results.append((url, result))

            status = f"{Fore.RED}PHISHING{Style.RESET_ALL}" if result['is_phishing'] == 1 else f"{Fore.GREEN}SAFE{Style.RESET_ALL}"
            print(f"{i}. {url[:50]:50} → {status}")

        # Summary
        phishing = sum(1 for _, r in results if r['is_phishing'] == 1)
        safe = len(results) - phishing

        print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"  {Fore.RED}Phishing: {phishing}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Safe: {safe}{Style.RESET_ALL}")

    def batch_check(self):
        """Batch check from file"""
        if not self.models_loaded:
            print(f"\n{Fore.RED}[x] Models not loaded. Please train first (option 1).{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}BATCH URL ANALYSIS{Style.RESET_ALL}\n")

        filepath = input(f"{Fore.YELLOW}Enter file path (one URL per line): {Style.RESET_ALL}").strip()

        if not os.path.exists(filepath):
            print(f"{Fore.RED}Error: File not found{Style.RESET_ALL}")
            return

        with open(filepath, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]

        print(f"\n{Fore.CYAN}Found {len(urls)} URLs to analyze...{Style.RESET_ALL}\n")

        results = []
        for i, url in enumerate(urls, 1):
            print(f"{Fore.CYAN}[{i}/{len(urls)}]{Style.RESET_ALL} {url[:40]}...", end=' ', flush=True)
            result = self.predictor.predict_single_url(url)
            results.append(result)

            if result['is_phishing'] == 1:
                print(f"{Fore.RED}PHISHING{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}SAFE{Style.RESET_ALL}")

            time.sleep(0.05)

        # Summary
        print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}BATCH ANALYSIS SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

        phishing = sum(1 for r in results if r['is_phishing'] == 1)
        safe = sum(1 for r in results if r['is_phishing'] == 0)
        errors = sum(1 for r in results if r['error'])

        print(f"{Fore.RED}[PHISHING] Phishing URLs: {phishing}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[SAFE] Safe URLs: {safe}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!]  Errors: {errors}{Style.RESET_ALL}\n")

        # Export option
        export = input(f"{Fore.YELLOW}Export to CSV? (y/n): {Style.RESET_ALL}").lower()
        if export == 'y':
            filename = f"batch_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            data = [{
                'URL': r['url'],
                'Prediction': 'PHISHING' if r['is_phishing'] == 1 else 'SAFE',
                'Confidence': f"{r['confidence']:.4f}",
                'Error': r['error'] or ''
            } for r in results]

            df = pd.DataFrame(data)
            df.to_csv(filename, index=False)
            print(f"{Fore.GREEN}[+] Exported to {filename}{Style.RESET_ALL}")

    def compare_urls(self):
        """Compare multiple URLs side by side"""
        if not self.models_loaded:
            print(f"\n{Fore.RED}[x] Models not loaded. Please train first (option 1).{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}URL COMPARISON TOOL{Style.RESET_ALL}\n")

        url1 = input(f"{Fore.YELLOW}First URL: {Style.RESET_ALL}").strip()
        url2 = input(f"{Fore.YELLOW}Second URL: {Style.RESET_ALL}").strip()

        if not url1 or not url2:
            return

        print(f"\n{Fore.CYAN}Comparing URLs...{Style.RESET_ALL}\n")

        r1 = self.predictor.predict_single_url(url1)
        r2 = self.predictor.predict_single_url(url2)

        print(f"{Fore.WHITE}URL 1:{Style.RESET_ALL} {url1}")
        status1 = f"{Fore.RED}PHISHING{Style.RESET_ALL}" if r1['is_phishing'] == 1 else f"{Fore.GREEN}SAFE{Style.RESET_ALL}"
        print(f"  Status: {status1} ({r1['confidence']*100:.1f}%)")
        print(f"  Risk Factors: {len(r1['risk_factors'])}\n")

        print(f"{Fore.WHITE}URL 2:{Style.RESET_ALL} {url2}")
        status2 = f"{Fore.RED}PHISHING{Style.RESET_ALL}" if r2['is_phishing'] == 1 else f"{Fore.GREEN}SAFE{Style.RESET_ALL}"
        print(f"  Status: {status2} ({r2['confidence']*100:.1f}%)")
        print(f"  Risk Factors: {len(r2['risk_factors'])}\n")

        if r1['is_phishing'] != r2['is_phishing']:
            safer = "First" if r1['is_phishing'] == 0 else "Second"
            print(f"{Fore.GREEN}[+] {safer} URL is safer{Style.RESET_ALL}")

    def test_samples(self):
        """Test with sample URLs - Demonstrates new detection features including IDN homographs"""
        if not self.models_loaded:
            print(f"\n{Fore.RED}[x] Models not loaded. Please train first (option 1).{Style.RESET_ALL}")
            return

        # Comprehensive test cases showcasing new features
        samples = [
            # === LEGITIMATE URLS ===
            ("https://www.google.com", "Legitimate Google", "safe"),
            ("https://www.paypal.com", "Legitimate PayPal", "safe"),
            ("https://www.amazon.com", "Legitimate Amazon", "safe"),

            # === IDN HOMOGRAPH ATTACKS (NEW!) ===
            ("https://pаypal.com/login", "IDN: Cyrillic 'а' in paypal", "idn"),
            ("https://gооgle.com", "IDN: Greek omicrons in google", "idn"),
            ("https://аpple.com", "IDN: Cyrillic 'а' in apple", "idn"),
            ("https://micrоsoft.com", "IDN: Cyrillic 'о' in microsoft", "idn"),

            # === PUNYCODE ATTACKS (NEW!) ===
            ("https://xn--pple-43d.com", "Punycode encoding (encoded domain)", "punycode"),

            # === NUMERIC SUBSTITUTION (NEW!) ===
            ("https://g00gle.com", "Numeric: zeros for 'o'", "numeric"),
            ("https://paypa1.com", "Numeric: 1 for 'l'", "numeric"),

            # === BRAND IMPERSONATION ===
            ("https://paypal-secure.tk/login", "Brand + suspicious TLD (.tk)", "brand"),
            ("https://secure-amazon.xyz/account", "Brand + suspicious TLD (.xyz)", "brand"),
            ("https://apple.verify-account.com/login", "Brand in subdomain", "brand"),
            ("https://microsoft-login.ml/signin", "Brand with hyphen + .ml TLD", "brand"),

            # === TYPOSQUATTING ===
            ("https://www.paypai.com/login", "Typosquatting - paypai", "typo"),

            # === PHISHING KEYWORDS ===
            ("https://account-verify-secure.com/confirm", "Phishing keywords", "keyword"),
            ("https://update-billing.tk/suspended-account", "Keywords + suspicious TLD", "keyword"),

            # === SUSPICIOUS PATTERNS ===
            ("https://192.168.1.1:8080/login.php", "IP + suspicious port", "suspicious"),
            ("https://paypal.phishing.com/login", "PayPal in subdomain", "suspicious"),
        ]

        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}COMPREHENSIVE PHISHING DETECTION TEST SUITE{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Testing Enhanced Features: IDN Homographs, Punycode, Brand Impersonation{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

        # Track statistics
        stats = {
            'total': 0,
            'detected': 0,
            'idn_detected': 0,
            'punycode_detected': 0,
            'safe_passed': 0
        }

        current_category = None

        for url, description, category in samples:
            # Print category headers
            if category != current_category:
                current_category = category
                category_names = {
                    'safe': '✓ LEGITIMATE SITES',
                    'idn': '⚠️  IDN HOMOGRAPH ATTACKS (Enhanced Detection)',
                    'punycode': '⚠️  PUNYCODE ATTACKS (Enhanced Detection)',
                    'numeric': '⚠️  NUMERIC SUBSTITUTION ATTACKS',
                    'brand': '⚠️  BRAND IMPERSONATION',
                    'typo': '⚠️  TYPOSQUATTING',
                    'keyword': '⚠️  PHISHING KEYWORDS',
                    'suspicious': '⚠️  SUSPICIOUS PATTERNS'
                }
                if category in category_names:
                    print(f"\n{Fore.CYAN}═══ {category_names[category]} ═══{Style.RESET_ALL}\n")

            result = self.predictor.predict_single_url(url)
            stats['total'] += 1

            if result['error']:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {url}")
                print(f"  {description}")
                continue

            # Status
            if result['is_phishing'] == 1:
                status = f"{Fore.RED}[PHISHING]{Style.RESET_ALL}"
                stats['detected'] += 1
            else:
                status = f"{Fore.GREEN}[SAFE]{Style.RESET_ALL}"
                if category == 'safe':
                    stats['safe_passed'] += 1

            confidence = result['confidence'] * 100

            print(f"{status} {description}")
            print(f"  URL: {url}")
            print(f"  Confidence: {confidence:.1f}%")

            # Show key detections with enhanced IDN info
            features = result['features']
            detections = []

            # IDN Homograph detection (Enhanced)
            if features.get('is_idn_homograph', 0) == 1:
                idn_score = features.get('idn_homograph_score', 0)
                detections.append(f"⚡ IDN Homograph (score: {idn_score:.2f})")
                stats['idn_detected'] += 1

            # Punycode detection (Enhanced)
            if features.get('has_punycode', 0) == 1:
                punycode_sim = features.get('punycode_brand_similarity', 0)
                detections.append(f"⚡ Punycode (brand similarity: {punycode_sim:.2f})")
                stats['punycode_detected'] += 1

            # Mixed scripts (Enhanced)
            if features.get('mixed_scripts', 0) == 1:
                detections.append("⚡ Mixed Character Sets")

            # Other detections
            if features.get('likely_brand_impersonation', 0) == 1:
                detections.append(f"Brand Impersonation ({features.get('brand_impersonation_score', 0):.2f})")
            if features.get('phishing_keyword_match', 0) == 1:
                detections.append("Phishing Keywords")
            if features.get('typosquatting_detected', 0) == 1:
                detections.append("Typosquatting")
            if features.get('is_suspicious_tld', 0) == 1:
                detections.append("Suspicious TLD")

            if detections:
                print(f"  Detections: {', '.join(detections)}")

            # Show top 2 risk factors
            if result['risk_factors']:
                print(f"  Top Risks:")
                for i, factor in enumerate(result['risk_factors'][:2], 1):
                    print(f"    {i}. {factor}")

            print()

        # Summary statistics
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}TEST SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

        detection_rate = (stats['detected'] / (stats['total'] - 3)) * 100 if stats['total'] > 3 else 0
        safe_rate = (stats['safe_passed'] / 3) * 100 if stats['total'] >= 3 else 0

        print(f"{Fore.GREEN}Total Tests: {stats['total']}{Style.RESET_ALL}")
        print(f"{Fore.RED}Phishing Detected: {stats['detected']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚡ IDN Homographs Detected: {stats['idn_detected']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚡ Punycode Attacks Detected: {stats['punycode_detected']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Legitimate Sites Passed: {stats['safe_passed']}/3{Style.RESET_ALL}")
        print(f"\nDetection Rate: {detection_rate:.1f}%")
        print(f"Legitimate Pass Rate: {safe_rate:.1f}%")

        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[i] Enhanced Detection Capabilities:{Style.RESET_ALL}")
        print(f"  ⚡ IDN Homograph Detection (80+ Unicode confusables)")
        print(f"     - Cyrillic confusables: а, е, о, р, с, х, у")
        print(f"     - Greek confusables: α, ε, ο, ρ, υ, χ")
        print(f"     - Mixed character set detection")
        print(f"  ⚡ Punycode Analysis (xn-- domains)")
        print(f"     - Automatic decoding")
        print(f"     - Brand similarity scoring")
        print(f"  ⚡ Brand Impersonation (19 brands)")
        print(f"  ⚡ Typosquatting Detection")
        print(f"  ⚡ Phishing Keyword Matching")
        print(f"  ⚡ Suspicious TLD Detection")
        print(f"  ⚡ 4 Free Dataset Sources (20K+ URLs)")
        print(f"\n  {Fore.GREEN}✓ All features work WITHOUT API keys{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

    def view_performance(self):
        """View model performance"""
        import joblib

        path = os.path.join('..', 'models', 'evaluation_results.pkl')
        if not os.path.exists(path):
            print(f"\n{Fore.RED}No evaluation results found.{Style.RESET_ALL}")
            return

        results = joblib.load(path)

        print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}MODEL PERFORMANCE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

        data = []
        for name, metrics in results.items():
            data.append({
                'Model': name.replace('_', ' ').title(),
                'Accuracy': f"{metrics['accuracy']:.4f}",
                'Precision': f"{metrics['precision']:.4f}",
                'Recall': f"{metrics['recall']:.4f}",
                'F1': f"{metrics['f1_score']:.4f}"
            })

        df = pd.DataFrame(data)
        print(df.to_string(index=False))
        print()

    def generate_report(self):
        """Generate performance report"""
        print(f"\n{Fore.CYAN}Generating comprehensive report...{Style.RESET_ALL}\n")

        try:
            # Import generate_report module
            import joblib

            parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            results_path = os.path.join(parent_dir, 'models', 'evaluation_results.pkl')

            if not os.path.exists(results_path):
                print(f"{Fore.RED}Error: No evaluation results found. Train models first.{Style.RESET_ALL}")
                return

            results = joblib.load(results_path)

            # Load training times if available
            times_path = os.path.join(parent_dir, 'models', 'training_times.pkl')
            training_times = {}
            if os.path.exists(times_path):
                training_times = joblib.load(times_path)

            # Generate report
            report = self._create_performance_report(results, training_times)

            # Save report
            report_path = os.path.join(parent_dir, 'MODEL_PERFORMANCE_REPORT.md')
            with open(report_path, 'w') as f:
                f.write(report)

            print(f"{Fore.GREEN}[+] Report generated: {report_path}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}Error generating report: {e}{Style.RESET_ALL}")

    def _create_performance_report(self, results, training_times):
        """Create performance report content"""
        from datetime import datetime

        report = f"""# ML Phishing URL Detector - Performance Report

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Model Performance Overview

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
|-------|----------|-----------|--------|----------|---------|
"""

        # Add model rows
        for name, metrics in sorted(results.items(), key=lambda x: x[1]['accuracy'], reverse=True):
            report += f"| {name.replace('_', ' ').title()} | {metrics['accuracy']:.4f} | {metrics['precision']:.4f} | {metrics['recall']:.4f} | {metrics['f1_score']:.4f} | {metrics['roc_auc']:.4f} |\n"

        report += "\n## Summary\n\n"

        # Find best models
        best_acc = max(results.items(), key=lambda x: x[1]['accuracy'])
        report += f"- **Best Accuracy**: {best_acc[0].replace('_', ' ').title()} ({best_acc[1]['accuracy']:.4f})\n"

        if training_times:
            report += "\n## Training Times\n\n"
            report += "| Model | Time (seconds) |\n"
            report += "|-------|----------------|\n"
            for name, time_val in sorted(training_times.items(), key=lambda x: x[1]):
                report += f"| {name.replace('_', ' ').title()} | {time_val:.2f} |\n"

        report += "\n---\n**Report End**\n"

        return report

    def view_viz_info(self):
        """Show visualization info"""
        viz_path = os.path.join('..', 'visualizations')

        print(f"\n{Fore.CYAN}VISUALIZATION FILES{Style.RESET_ALL}\n")

        if os.path.exists(viz_path):
            print(f"{Fore.GREEN}[+] Visualizations available in: {viz_path}{Style.RESET_ALL}\n")
            print(f"   confusion_matrices/    - Confusion matrices for all models")
            print(f"   roc_curves/            - ROC and PR curves")
            print(f"   feature_importance/    - Feature importance plots")
            print(f"   performance_metrics/   - Model comparison charts")
        else:
            print(f"{Fore.YELLOW}[!] No visualizations found. Train models first.{Style.RESET_ALL}")

    def display_detailed_result(self, result):
        """Display detailed URL analysis"""
        url = result['url']
        is_phishing = result['is_phishing']
        confidence = result['confidence']
        features = result['features']
        risk_factors = result['risk_factors']
        individual_probs = result['individual_probabilities']

        # Feature explanations
        explanations = self.predictor.get_feature_explanation(features)

        # Display features
        print(f"{Fore.WHITE}[FEATURES] URL FEATURES:{Style.RESET_ALL}")
        print(f"   [+] Length: {explanations['URL Length']}")
        print(f"   [+] Protocol: {explanations['Protocol']}")
        print(f"   [+] TLD Type: {explanations['TLD Type']}")
        print(f"   [+] Subdomains: {explanations['Subdomain Count']}")
        print(f"   [+] Suspicious Keywords: {explanations['Suspicious Keywords']}")
        print(f"   [+] Entropy: {explanations['URL Entropy']}\n")

        # Model predictions
        print(f"{Fore.WHITE}[AI] MODEL PREDICTIONS:{Style.RESET_ALL}\n")

        for model, prob in list(individual_probs.items())[:3]:
            pred = result['individual_predictions'][model]
            pred_text = "PHISHING" if pred == 1 else "SAFE"
            color = Fore.RED if pred == 1 else Fore.GREEN
            print(f"   {model.replace('_', ' ').title():20} {color}{pred_text}{Style.RESET_ALL} ({prob*100:.1f}%)")

        print(f"\n   {Fore.WHITE}Ensemble:{Style.RESET_ALL} ", end="")

        if is_phishing == 1:
            print(f"{Fore.RED}[PHISHING] PHISHING{Style.RESET_ALL} ({confidence*100:.1f}%)")
        else:
            print(f"{Fore.GREEN}[SAFE] SAFE{Style.RESET_ALL} ({confidence*100:.1f}%)")

        print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

        # Final verdict
        if is_phishing == 1:
            print(f"{Fore.RED}{Back.RED}{Style.BRIGHT}  [!]  PHISHING DETECTED - DO NOT VISIT  {Style.RESET_ALL}\n")
        else:
            print(f"{Fore.GREEN}{Back.GREEN}{Style.BRIGHT}  [OK]  URL APPEARS SAFE  {Style.RESET_ALL}\n")

        # Risk factors
        if risk_factors:
            print(f"{Fore.YELLOW}[ALERT] RISK FACTORS:{Style.RESET_ALL}")
            for factor in risk_factors[:5]:
                print(f"   • {factor}")
            print()

    def run(self):
        """Main application loop"""
        self.print_banner()

        while True:
            try:
                choice = self.print_main_menu()

                if choice == '0':
                    print(f"\n{Fore.CYAN}Thank you for using ML Phishing Detector!{Style.RESET_ALL}\n")
                    break
                elif choice == '1':
                    self.train_models()
                elif choice == '2':
                    self.check_single_url()
                elif choice == '3':
                    self.batch_check()
                elif choice == '4':
                    self.quick_check()
                elif choice == '5':
                    self.check_multiple_urls()
                elif choice == '6':
                    self.view_performance()
                elif choice == '7':
                    self.generate_report()
                elif choice == '8':
                    print(f"\n{Fore.YELLOW}History feature coming soon!{Style.RESET_ALL}\n")
                elif choice == '9':
                    print(f"\n{Fore.YELLOW}Use batch check (option 3) for export{Style.RESET_ALL}\n")
                elif choice == '10':
                    self.compare_urls()
                elif choice == '11':
                    self.test_samples()
                elif choice == '12':
                    self.view_viz_info()
                else:
                    print(f"\n{Fore.RED}Invalid choice. Please enter 0-12.{Style.RESET_ALL}\n")

                if choice in ['2', '3', '4', '5', '6', '7', '10', '11', '12']:
                    input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
                    print("\n")

            except KeyboardInterrupt:
                print(f"\n\n{Fore.YELLOW}Interrupted by user{Style.RESET_ALL}\n")
                break
            except Exception as e:
                print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}\n")


if __name__ == '__main__':
    app = PhishingDetector()
    app.run()
