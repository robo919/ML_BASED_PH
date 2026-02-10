"""
Build Executable - Phishing Detector v3.0
Creates standalone .exe file using PyInstaller
"""

import sys
import os
import subprocess

def print_header(text):
    """Print section header"""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80 + "\n")

def check_pyinstaller():
    """Check if PyInstaller is installed"""
    print("Checking for PyInstaller...")
    try:
        import PyInstaller
        print(f"✓ PyInstaller {PyInstaller.__version__} is installed")
        return True
    except ImportError:
        print("✗ PyInstaller is not installed")
        print("\nTo install PyInstaller:")
        print("  pip install pyinstaller")
        return False

def build_gui_executable():
    """Build GUI executable"""
    print_header("Building GUI Executable")

    print("This will create a standalone .exe file for the GUI")
    print("Output: dist/PhishingDetectorGUI.exe")
    print("\nThis may take 5-10 minutes...\n")

    response = input("Continue? (y/n): ").lower().strip()
    if response != 'y':
        print("Cancelled.")
        return False

    print("\n🔨 Building executable...")
    print("Please wait, this may take several minutes...\n")

    # PyInstaller command
    cmd = [
        'pyinstaller',
        '--onefile',                # Single executable
        '--windowed',               # No console window
        '--name=PhishingDetectorGUI',
        '--icon=NONE',              # Add icon path if you have one
        '--add-data=src;src',       # Include source files
        '--add-data=models;models', # Include models
        '--add-data=data;data',     # Include data
        '--hidden-import=dns',
        '--hidden-import=dns.resolver',
        '--hidden-import=tldextract',
        '--hidden-import=Levenshtein',
        '--hidden-import=sklearn',
        '--hidden-import=xgboost',
        '--hidden-import=tkinter',
        'gui_ultra.py'
    ]

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(result.stdout)

        print("\n✅ BUILD SUCCESSFUL!")
        print(f"\nExecutable created: dist\\PhishingDetectorGUI.exe")
        print(f"Size: ~{os.path.getsize('dist/PhishingDetectorGUI.exe') / (1024*1024):.1f} MB")
        print("\nYou can now distribute this file to users!")
        return True

    except subprocess.CalledProcessError as e:
        print(f"\n❌ BUILD FAILED!")
        print(f"Error: {e}")
        print(f"\nOutput:\n{e.stdout}")
        print(f"\nError:\n{e.stderr}")
        return False

def build_launcher_executable():
    """Build launcher executable"""
    print_header("Building Launcher Executable")

    print("This will create a standalone .exe file for the launcher")
    print("Output: dist/PhishingDetector.exe")
    print("\nThis may take 5-10 minutes...\n")

    response = input("Continue? (y/n): ").lower().strip()
    if response != 'y':
        print("Cancelled.")
        return False

    print("\n🔨 Building executable...")
    print("Please wait, this may take several minutes...\n")

    # PyInstaller command
    cmd = [
        'pyinstaller',
        '--onefile',                # Single executable
        '--console',                # Keep console for menu
        '--name=PhishingDetector',
        '--icon=NONE',              # Add icon path if you have one
        '--add-data=src;src',
        '--add-data=models;models',
        '--add-data=data;data',
        '--add-data=bin;bin',
        '--hidden-import=dns',
        '--hidden-import=dns.resolver',
        '--hidden-import=tldextract',
        '--hidden-import=Levenshtein',
        '--hidden-import=sklearn',
        '--hidden-import=xgboost',
        '--hidden-import=tkinter',
        'launcher.py'
    ]

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(result.stdout)

        print("\n✅ BUILD SUCCESSFUL!")
        print(f"\nExecutable created: dist\\PhishingDetector.exe")
        print(f"Size: ~{os.path.getsize('dist/PhishingDetector.exe') / (1024*1024):.1f} MB")
        print("\nYou can now distribute this file to users!")
        return True

    except subprocess.CalledProcessError as e:
        print(f"\n❌ BUILD FAILED!")
        print(f"Error: {e}")
        print(f"\nOutput:\n{e.stdout}")
        print(f"\nError:\n{e.stderr}")
        return False

def main():
    """Main build script"""
    print_header("PHISHING DETECTOR v3.0 - EXECUTABLE BUILDER")

    # Check PyInstaller
    if not check_pyinstaller():
        print("\nPlease install PyInstaller and try again.")
        return

    print("\nWhat would you like to build?\n")
    print("  1. GUI Executable (PhishingDetectorGUI.exe)")
    print("  2. Launcher Executable (PhishingDetector.exe)")
    print("  3. Both")
    print("  0. Cancel")
    print()

    choice = input("Select option (0-3): ").strip()

    if choice == '1':
        build_gui_executable()
    elif choice == '2':
        build_launcher_executable()
    elif choice == '3':
        build_gui_executable()
        build_launcher_executable()
    elif choice == '0':
        print("Cancelled.")
    else:
        print("Invalid option.")

    print("\n" + "=" * 80)
    print()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nBuild cancelled by user.")
    except Exception as e:
        print(f"\n\nERROR: {e}")
        import traceback
        traceback.print_exc()
