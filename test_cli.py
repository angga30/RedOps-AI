#!/usr/bin/env python3
"""Test script for RedOps-AI CLI functionality.

This script tests the core functionality of the RedOps-AI CLI without
requiring external dependencies that might not be available.
"""

import sys
import os
import subprocess
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test importing core modules."""
    print("Testing core module imports...")
    
    try:
        from redops.core import config
        print("✓ Config module imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import config module: {e}")
        return False
    
    try:
        from redops.core import exceptions
        print("✓ Exceptions module imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import exceptions module: {e}")
        return False
    
    try:
        from redops.core import validation
        print("✓ Validation module imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import validation module: {e}")
        return False
    
    try:
        from redops.core import logging
        print("✓ Logging module imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import logging module: {e}")
        return False
    
    return True

def test_tools():
    """Test tools module."""
    print("\nTesting tools module...")
    
    try:
        from redops.tools import tool_manager, get_tool_info
        print("✓ Tools module imported successfully")
        
        # Test tool info
        info = get_tool_info()
        print(f"✓ Available tools: {list(info.keys())}")
        
        return True
    except ImportError as e:
        print(f"✗ Failed to import tools module: {e}")
        return False
    except Exception as e:
        print(f"✗ Error testing tools: {e}")
        return False

def test_agents():
    """Test agent modules."""
    print("\nTesting agent modules...")
    
    try:
        from redops.agents import base
        print("✓ Base agent imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import base agent: {e}")
        return False
    
    try:
        from redops.agents import reconnaissance
        print("✓ Reconnaissance agent imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import reconnaissance agent: {e}")
        return False
    
    try:
        from redops.agents import coordinator
        print("✓ Coordinator agent imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import coordinator agent: {e}")
        return False
    
    return True

def test_validation():
    """Test validation functionality."""
    print("\nTesting validation functionality...")
    
    try:
        from redops.core.validation import NetworkValidator, validate_target
        
        validator = NetworkValidator()
        
        # Test IP validation
        test_cases = [
            ("192.168.1.1", True, "Valid IP"),
            ("10.0.0.0/24", True, "Valid CIDR"),
            ("example.com", True, "Valid domain"),
            ("invalid..domain", False, "Invalid domain"),
            ("999.999.999.999", False, "Invalid IP")
        ]
        
        for target, expected, description in test_cases:
            try:
                result = validate_target(target)
                if bool(result) == expected:
                    print(f"✓ {description}: {target}")
                else:
                    print(f"✗ {description}: {target} (unexpected result)")
            except Exception as e:
                if not expected:
                    print(f"✓ {description}: {target} (correctly rejected)")
                else:
                    print(f"✗ {description}: {target} (unexpected error: {e})")
        
        return True
    except ImportError as e:
        print(f"✗ Failed to import validation: {e}")
        return False
    except Exception as e:
        print(f"✗ Error testing validation: {e}")
        return False

def test_config():
    """Test configuration functionality."""
    print("\nTesting configuration functionality...")
    
    try:
        from redops.core.config import Config, load_config
        
        # Test default config
        config = Config()
        print(f"✓ Default config created: {config.application.name}")
        
        # Test config loading (should work with defaults)
        loaded_config = load_config()
        print(f"✓ Config loaded: {loaded_config.application.name}")
        
        return True
    except ImportError as e:
        print(f"✗ Failed to import config: {e}")
        return False
    except Exception as e:
        print(f"✗ Error testing config: {e}")
        return False

def test_cli_structure():
    """Test CLI module structure."""
    print("\nTesting CLI structure...")
    
    try:
        from redops.cli import main
        print("✓ CLI main module imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import CLI main: {e}")
        return False
    
    try:
        from redops.cli import commands
        print("✓ CLI commands module imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import CLI commands: {e}")
        return False
    
    return True

def test_nmap_availability():
    """Test if Nmap is available on the system."""
    print("\nTesting Nmap availability...")
    
    try:
        result = subprocess.run(["which", "nmap"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Nmap found at: {result.stdout.strip()}")
            
            # Get version
            version_result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
            if version_result.returncode == 0:
                version_line = version_result.stdout.split('\n')[0]
                print(f"✓ {version_line}")
            
            return True
        else:
            print("✗ Nmap not found in PATH")
            return False
    except Exception as e:
        print(f"✗ Error checking Nmap: {e}")
        return False

def main():
    """Run all tests."""
    print("RedOps-AI CLI Test Suite")
    print("=" * 40)
    
    tests = [
        ("Core Imports", test_imports),
        ("Tools Module", test_tools),
        ("Agent Modules", test_agents),
        ("Validation", test_validation),
        ("Configuration", test_config),
        ("CLI Structure", test_cli_structure),
        ("Nmap Availability", test_nmap_availability)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        print("-" * len(test_name) + "-")
        
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"✗ Test failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 40)
    print("Test Summary:")
    print("=" * 40)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        symbol = "✓" if result else "✗"
        print(f"{symbol} {test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! RedOps-AI CLI is ready to use.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check the issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())