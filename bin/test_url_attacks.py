"""
URL Attack Classification Test Suite
Tests all attack types with proper naming and detection
"""

import sys
import os

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Add source directory to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from url_attack_classifier import URLAttackClassifier, AttackType, AttackCategory


def print_attack_reference():
    """Print attack types reference"""
    print("=" * 80)
    print("URL-BASED ATTACK TYPES REFERENCE")
    print("=" * 80)

    reference = """
CATEGORY 1: DOMAIN MANIPULATION
-------------------------------
TYPOSQUATTING_OMISSION      Missing character       gogle.com (missing o)
TYPOSQUATTING_INSERTION     Extra character         gooogle.com (extra o)
TYPOSQUATTING_SUBSTITUTION  Wrong character         paypa1.com (l->1)
TYPOSQUATTING_TRANSPOSITION Swapped characters      googel.com (el->le)
TYPOSQUATTING_KEYBOARD      Adjacent key            goigle.com (o->i)
BITSQUATTING                Bit flip error          goofle.com
DOPPELGANGER_DOMAIN         Missing dot             wwwgoogle.com

CATEGORY 2: HOMOGRAPH ATTACKS
-----------------------------
IDN_HOMOGRAPH_CYRILLIC      Cyrillic lookalikes     google.com (Cyrillic o)
IDN_HOMOGRAPH_GREEK         Greek lookalikes        googIe.com (Greek I)
PUNYCODE_ATTACK             xn-- encoded            xn--ggle-55da.com
MIXED_SCRIPT_ATTACK         Multiple scripts        Mixing Latin+Cyrillic

CATEGORY 3: BRAND EXPLOITATION
------------------------------
COMBOSQUATTING              Brand + keyword         paypal-login.com
LEVELSQUATTING              Brand as subdomain      paypal.evil.com
SOUNDSQUATTING              Homophone attack        4pple.com (sounds like apple)
BRAND_TLD_SWAP              Suspicious TLD          google.tk, paypal.ml

CATEGORY 4: URL STRUCTURE ABUSE
-------------------------------
SUBDOMAIN_ABUSE             Fake subdomain          google.com.evil.site
PATH_MANIPULATION           Brand in path           evil.com/google.com/login
URL_SHORTENER_ABUSE         Hidden destination      bit.ly/xyz
CREDENTIAL_HARVESTING       Embedded credentials    user:pass@evil.com

CATEGORY 5: TECHNICAL DECEPTION
-------------------------------
IP_ADDRESS_URL              Direct IP               http://192.168.1.1/login
HEX_IP_ADDRESS              Hex encoded IP          0x7f.0x0.0x0.0x1
URL_ENCODING_ABUSE          Percent encoding        %70aypal.com
DOUBLE_ENCODING             Double encoded          %2570aypal.com

CATEGORY 6: VISUAL DECEPTION
----------------------------
ZERO_WIDTH_CHARS            Invisible chars         goo[invisible]gle.com
RTLO_ATTACK                 Right-to-left override  moc.elgoog (reversed)
CONFUSABLE_CHARS            l vs 1, O vs 0          paypa1.com
"""
    print(reference)
    print("=" * 80)


def run_tests():
    """Run comprehensive tests"""
    print("\n" + "=" * 80)
    print("URL ATTACK CLASSIFICATION TEST SUITE")
    print("=" * 80 + "\n")

    classifier = URLAttackClassifier()

    test_cases = [
        # TYPOSQUATTING
        ("https://gogle.com", AttackType.TYPOSQUATTING_OMISSION, "google"),
        ("https://gooogle.com", AttackType.TYPOSQUATTING_INSERTION, "google"),
        ("https://googel.com", AttackType.TYPOSQUATTING_TRANSPOSITION, "google"),
        ("https://paypa1.com", AttackType.TYPOSQUATTING_SUBSTITUTION, "paypal"),
        ("https://faceboook.com", AttackType.TYPOSQUATTING_INSERTION, "facebook"),
        ("https://mircosoft.com", AttackType.TYPOSQUATTING_TRANSPOSITION, "microsoft"),
        ("https://netfilx.com", AttackType.TYPOSQUATTING_TRANSPOSITION, "netflix"),
        ("https://twiter.com", AttackType.TYPOSQUATTING_OMISSION, "twitter"),

        # COMBOSQUATTING
        ("https://paypal-login.com", AttackType.COMBOSQUATTING, "paypal"),
        ("https://google-secure.com", AttackType.COMBOSQUATTING, "google"),
        ("https://amazon-verify.com", AttackType.COMBOSQUATTING, "amazon"),
        ("https://apple-support.com", AttackType.COMBOSQUATTING, "apple"),
        ("https://microsoft-account.com", AttackType.COMBOSQUATTING, "microsoft"),

        # LEVELSQUATTING
        ("https://paypal.evil.com", AttackType.LEVELSQUATTING, "paypal"),
        ("https://google.malware.tk", AttackType.LEVELSQUATTING, "google"),
        ("https://amazon.secure-login.com", AttackType.LEVELSQUATTING, "amazon"),
        ("https://chase.banking.info", AttackType.LEVELSQUATTING, "chase"),

        # BRAND TLD SWAP
        ("https://google.tk", AttackType.BRAND_TLD_SWAP, "google"),
        ("https://paypal.ml", AttackType.BRAND_TLD_SWAP, "paypal"),
        ("https://facebook.cf", AttackType.BRAND_TLD_SWAP, "facebook"),

        # TECHNICAL DECEPTION
        ("http://192.168.1.1/login", AttackType.IP_ADDRESS_URL, None),
        ("http://10.0.0.1/paypal", AttackType.IP_ADDRESS_URL, None),

        # URL SHORTENERS
        ("https://bit.ly/xyz123", AttackType.URL_SHORTENER_ABUSE, None),
        ("https://tinyurl.com/abc", AttackType.URL_SHORTENER_ABUSE, None),
        ("https://t.co/xyz", AttackType.URL_SHORTENER_ABUSE, None),

        # LEGITIMATE (should NOT be flagged)
        ("https://www.google.com", AttackType.LEGITIMATE, None),
        ("https://www.paypal.com", AttackType.LEGITIMATE, None),
        ("https://github.com", AttackType.LEGITIMATE, None),
        ("https://amazon.com", AttackType.LEGITIMATE, None),
        ("https://microsoft.com", AttackType.LEGITIMATE, None),
        ("https://apple.com", AttackType.LEGITIMATE, None),
    ]

    results = {
        'passed': 0,
        'failed': 0,
        'total': len(test_cases)
    }

    category_results = {}

    for url, expected_type, expected_brand in test_cases:
        result = classifier.classify_url(url)

        # Check if correct
        type_match = False
        if expected_type == AttackType.LEGITIMATE:
            type_match = result.attack_type == AttackType.LEGITIMATE
        else:
            # For attacks, check if the general category matches
            type_match = (result.attack_type == expected_type) or \
                        (expected_type.value.startswith("TYPOSQUATTING") and
                         result.attack_type.value.startswith("TYPOSQUATTING"))

        brand_match = (expected_brand is None) or (result.target_brand == expected_brand)
        is_correct = type_match and brand_match

        if is_correct:
            results['passed'] += 1
            status = "PASS"
        else:
            results['failed'] += 1
            status = "FAIL"

        # Track by category
        category = result.category.value
        if category not in category_results:
            category_results[category] = {'passed': 0, 'failed': 0}
        if is_correct:
            category_results[category]['passed'] += 1
        else:
            category_results[category]['failed'] += 1

        # Print result
        brand_info = f" -> {result.target_brand}" if result.target_brand else ""
        expected_brand_info = f" -> {expected_brand}" if expected_brand else ""

        print(f"[{status}] {url}")
        print(f"      Expected: {expected_type.value}{expected_brand_info}")
        print(f"      Got:      {result.attack_type.value}{brand_info}")
        print(f"      Severity: {result.severity} | Confidence: {result.confidence:.0%}")
        if not is_correct:
            print(f"      Description: {result.description}")
        print()

    # Summary
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"\nOverall Results:")
    print(f"  Passed: {results['passed']}/{results['total']} ({results['passed']/results['total']*100:.1f}%)")
    print(f"  Failed: {results['failed']}/{results['total']}")

    print(f"\nResults by Category:")
    for category, counts in sorted(category_results.items()):
        total = counts['passed'] + counts['failed']
        pct = counts['passed'] / total * 100 if total > 0 else 0
        print(f"  {category}: {counts['passed']}/{total} ({pct:.0f}%)")

    print("\n" + "=" * 80)

    if results['passed'] == results['total']:
        print("ALL TESTS PASSED! URL Attack Classification is working correctly!")
    else:
        print(f"WARNING: {results['failed']} tests failed. Review issues above.")

    print("=" * 80)

    return results['passed'] == results['total']


if __name__ == '__main__':
    print_attack_reference()
    success = run_tests()
    sys.exit(0 if success else 1)
