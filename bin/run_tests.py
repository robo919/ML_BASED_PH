"""
Test Runner - Phishing Detector v3.0
Runs all test suites: system tests and typosquatting tests
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

def print_header(text):
    """Print a section header"""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80 + "\n")

def run_system_tests():
    """Run system tests"""
    print_header("RUNNING SYSTEM TESTS")

    try:
        # Import test_system
        sys.path.insert(0, os.path.dirname(__file__))
        import test_system

        success = test_system.run_all_tests()
        return success
    except Exception as e:
        print(f"Error running system tests: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_typosquatting_tests():
    """Run typosquatting tests"""
    print_header("RUNNING TYPOSQUATTING TESTS")

    try:
        # Import test_typosquatting
        sys.path.insert(0, os.path.dirname(__file__))
        import test_typosquatting

        test_typosquatting.test_typosquatting()
        return True
    except Exception as e:
        print(f"Error running typosquatting tests: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main test runner"""
    print_header("PHISHING DETECTOR v3.0 - COMPLETE TEST SUITE")

    print("This will run all tests:")
    print("  1. System Tests (6 components)")
    print("  2. Typosquatting Tests (15 test cases)")
    print()

    response = input("Continue? (y/n): ").lower().strip()
    if response != 'y':
        print("\nTests cancelled.")
        return

    results = {
        'system_tests': False,
        'typosquatting_tests': False
    }

    # Run system tests
    results['system_tests'] = run_system_tests()

    # Run typosquatting tests
    results['typosquatting_tests'] = run_typosquatting_tests()

    # Final summary
    print_header("FINAL TEST SUMMARY")

    print("Test Suite Results:")
    print(f"  {'✓' if results['system_tests'] else '✗'} System Tests: {'PASSED' if results['system_tests'] else 'FAILED'}")
    print(f"  {'✓' if results['typosquatting_tests'] else '✗'} Typosquatting Tests: {'PASSED' if results['typosquatting_tests'] else 'FAILED'}")
    print()

    if all(results.values()):
        print("🎉 ALL TESTS PASSED! System is ready for production use!")
        return True
    else:
        print("⚠️ SOME TESTS FAILED. Please review errors above.")
        return False

if __name__ == '__main__':
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
