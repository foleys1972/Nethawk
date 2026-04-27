#!/usr/bin/env python3
"""
Build script for NetHawk Pro executable
"""

import subprocess
import sys
import os
import shutil

def main():
    print("=" * 50)
    print("Building NetHawk Pro Executable")
    print("=" * 50)
    print()
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print(f"✓ PyInstaller found: {PyInstaller.__version__}")
    except ImportError:
        print("Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
    
    # Check if spec file exists
    if not os.path.exists('nethawk2_2.spec'):
        print("ERROR: nethawk2_2.spec not found!")
        return 1
    
    # Check if icon file exists
    if not os.path.exists('nethawk.ico'):
        print("WARNING: nethawk.ico not found!")
        print("The executable will be built without a custom icon")
    else:
        print(f"✓ Icon file found: nethawk.ico")
    
    # Clean previous builds
    print("\nCleaning previous builds...")
    for dir_name in ['build', 'dist', '__pycache__']:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"  Removed {dir_name}/")
    
    # Build the executable
    print("\nBuilding executable...")
    print("This may take a few minutes...")
    print()
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "PyInstaller",
            "--clean",
            "nethawk2_2.spec"
        ])
        
        exe_path = os.path.join('dist', 'Nethawk.exe')
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024 * 1024)
            print()
            print("=" * 50)
            print("Build Complete!")
            print("=" * 50)
            print(f"Executable: {exe_path}")
            print(f"Size: {size_mb:.1f} MB")
            print()
            print("You can now run: dist\\Nethawk.exe")
        else:
            print("ERROR: Executable not found!")
            return 1
            
    except subprocess.CalledProcessError as e:
        print(f"\nBuild failed with error: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

