"""
Test Advanced Typosquatting Detection
Tests all typosquatting techniques with real examples
"""

import sys
import os

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Add source directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from ultimate_predictor import UltimatePhishingPredictor

def print_section(title):
    """Print a section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")

def test_typosquatting():
    """Test typosquatting detection with various attack types"""

    print_section("ADVANCED TYPOSQUATTING DETECTION TEST SUITE")

    # Initialize predictor
    print("Initializing Ultimate Phishing Predictor...\n")
    predictor = UltimatePhishingPredictor()

    # Test cases covering all attack types
    test_cases = [
        # Character substitution
        ("https://paypa1.com", "Substitution", "l -> 1 in paypal"),
        ("https://micr0soft.com", "Substitution", "o -> 0 in microsoft"),

        # Character repetition
        ("https://gooogle.com", "Repetition", "Extra 'o' in google"),
        ("https://faceebook.com", "Repetition", "Extra 'e' in facebook"),

        # Character omission
        ("https://gogle.com", "Omission", "Missing 'o' in google"),
        ("https://aple.com", "Omission", "Missing 'p' in apple"),

        # Character transposition
        ("https://googel.com", "Transposition", "el -> le in google"),
        ("https://amaozn.com", "Transposition", "zo -> oz in amazon"),

        # IDN homograph (Cyrillic lookalikes)
        ("https://gооgle.com", "IDN Homograph", "Cyrillic о instead of Latin o"),
        ("https://аpple.com", "IDN Homograph", "Cyrillic а instead of Latin a"),

        # Combosquatting
        ("https://paypal-secure.com", "Combosquatting", "Brand + keyword"),
        ("https://google-login.com", "Combosquatting", "Brand + action"),
        ("https://microsoft-support.com", "Combosquatting", "Brand + service"),

        # Legitimate domains for comparison
        ("https://www.google.com", "Legitimate", "Official Google domain"),
        ("https://www.paypal.com", "Legitimate", "Official PayPal domain"),
    ]

    results_summary = {
        'total': len(test_cases),
        'detected': 0,
        'missed': 0,
        'false_positives': 0
    }

    for i, (url, attack_type, description) in enumerate(test_cases, 1):
        print(f"\n[Test {i}/{len(test_cases)}] {attack_type}")
        print("-" * 80)
        print(f"URL: {url}")
        print(f"Description: {description}")

        # Analyze URL (fast mode - no DNS)
        result = predictor.analyze_url_comprehensive(url, include_dns_check=False)

        # Display results
        print(f"\nVerdict: {result['final_verdict']}")
        print(f"Threat Level: {result['threat_level']}/100")
        print(f"Confidence: {result['confidence']:.1%}")

        # Check typosquatting detection
        if 'typosquatting_analysis' in result['layers']:
            typo = result['layers']['typosquatting_analysis']
            is_typosquat = typo['is_typosquatting']

            if is_typosquat:
                print(f"\n✓ TYPOSQUATTING DETECTED!")
                print(f"  Technique: {typo['technique']}")
                print(f"  Target Brand: {typo.get('target_brand', 'unknown')}")
                print(f"  Severity: {typo['severity']}")
                print(f"  Confidence: {typo['confidence']:.1%}")

                # Track statistics
                if attack_type != "Legitimate":
                    results_summary['detected'] += 1
                else:
                    results_summary['false_positives'] += 1
            else:
                print("\n✗ Typosquatting NOT detected")
                if attack_type != "Legitimate":
                    results_summary['missed'] += 1

        # Show top risk factors
        if result.get('risk_factors'):
            print(f"\nRisk Factors:")
            for factor in result['risk_factors'][:3]:
                print(f"  • {factor}")

    # Print summary
    print_section("TEST SUMMARY")

    legitimate_count = sum(1 for _, attack_type, _ in test_cases if attack_type == "Legitimate")
    attack_count = len(test_cases) - legitimate_count

    print(f"Total Tests: {results_summary['total']}")
    print(f"  - Attack Samples: {attack_count}")
    print(f"  - Legitimate Samples: {legitimate_count}")
    print()
    print(f"Detection Results:")
    print(f"  ✓ Attacks Detected: {results_summary['detected']}/{attack_count}")
    print(f"  ✗ Attacks Missed: {results_summary['missed']}/{attack_count}")
    print(f"  ⚠ False Positives: {results_summary['false_positives']}/{legitimate_count}")
    print()

    detection_rate = (results_summary['detected'] / attack_count * 100) if attack_count > 0 else 0
    false_positive_rate = (results_summary['false_positives'] / legitimate_count * 100) if legitimate_count > 0 else 0

    print(f"Performance Metrics:")
    print(f"  Detection Rate: {detection_rate:.1f}%")
    print(f"  False Positive Rate: {false_positive_rate:.1f}%")
    print()

    if detection_rate >= 90 and false_positive_rate <= 10:
        print("🎉 EXCELLENT! Typosquatting detection is working at production level!")
    elif detection_rate >= 80:
        print("✓ GOOD! Typosquatting detection is working well.")
    else:
        print("⚠ NEEDS IMPROVEMENT - Detection rate below 80%")

    print("\n" + "=" * 80)

if __name__ == '__main__':
    try:
        test_typosquatting()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
    except Exception as e:
        print(f"\n\nERROR: {e}")
        import traceback
        traceback.print_exc()
