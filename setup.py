#!/usr/bin/env python3
"""
RedOps-AI Setup Script

This script helps set up the RedOps-AI environment with proper dependencies
and configuration.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path


def print_banner():
    """Print the RedOps-AI setup banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                     RedOps-AI Setup                         ║
    ║              AI-Powered Red Team Operations                  ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def check_python_version():
    """Check if Python version is compatible."""
    print("[1/8] Checking Python version...")
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required.")
        print(f"   Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python {sys.version.split()[0]} is compatible.")


def check_nmap():
    """Check if Nmap is installed."""
    print("[2/8] Checking Nmap installation...")
    nmap_path = shutil.which('nmap')
    if not nmap_path:
        print("❌ Error: Nmap is not installed or not in PATH.")
        print("   Please install Nmap:")
        print("   - macOS: brew install nmap")
        print("   - Ubuntu/Debian: sudo apt-get install nmap")
        print("   - CentOS/RHEL: sudo yum install nmap")
        sys.exit(1)
    print(f"✅ Nmap found at: {nmap_path}")


def create_directories():
    """Create necessary directories."""
    print("[3/8] Creating directories...")
    directories = [
        'config',
        'logs',
        'results',
        'reports',
        'data',
        'tests/unit',
        'tests/integration'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"   Created: {directory}/")
    print("✅ Directories created successfully.")


def install_dependencies():
    """Install Python dependencies."""
    print("[4/8] Installing Python dependencies...")
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'], 
                      check=True, capture_output=True)
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                      check=True, capture_output=True)
        print("✅ Dependencies installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        print("   Please run manually: pip install -r requirements.txt")
        sys.exit(1)


def setup_environment():
    """Set up environment configuration."""
    print("[5/8] Setting up environment configuration...")
    
    if not Path('.env').exists():
        if Path('.env.example').exists():
            shutil.copy('.env.example', '.env')
            print("✅ Created .env file from .env.example")
            print("   Please edit .env file with your API keys and configuration.")
        else:
            print("⚠️  Warning: .env.example not found. Creating basic .env file.")
            with open('.env', 'w') as f:
                f.write("# RedOps-AI Environment Configuration\n")
                f.write("OPENAI_API_KEY=your_openai_api_key_here\n")
                f.write("REDOPS_ENVIRONMENT=development\n")
                f.write("REDOPS_DEBUG=true\n")
    else:
        print("✅ .env file already exists.")


def create_default_config():
    """Create default configuration file."""
    print("[6/8] Creating default configuration...")
    
    config_content = """
# RedOps-AI Configuration
application:
  name: "RedOps-AI"
  version: "1.0.0"
  environment: "development"
  debug: true

logging:
  level: "INFO"
  format: "json"
  file: "logs/redops.log"
  max_size: "10MB"
  backup_count: 5

ai:
  provider: "openai"  # or "anthropic"
  model: "gpt-4"
  temperature: 0.1
  max_tokens: 2000
  timeout: 120

tools:
  nmap:
    path: "/usr/bin/nmap"
    timeout: 300
    default_timing: 3
    max_ports: 1000

scanning:
  max_concurrent: 10
  default_ports: "1-1000"
  timeout: 600
  rate_limit: 10

output:
  directory: "results"
  format: "json"  # json, xml, txt
  include_raw: true
  compress: false

security:
  api_rate_limit: 60
  scan_rate_limit: 10
  max_target_size: 256  # CIDR block size limit
  allowed_networks:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.0/8"
"""
    
    config_path = Path('config/config.yaml')
    if not config_path.exists():
        with open(config_path, 'w') as f:
            f.write(config_content.strip())
        print("✅ Created default configuration file: config/config.yaml")
    else:
        print("✅ Configuration file already exists.")


def run_tests():
    """Run basic tests to verify installation."""
    print("[7/8] Running basic tests...")
    
    try:
        # Test basic imports
        import click
        import rich
        import yaml
        print("   ✅ Core dependencies imported successfully")
        
        # Test RedOps modules
        sys.path.insert(0, '.')
        from redops.core.config import Config
        from redops.core.validation import validate_target_simple
        print("   ✅ RedOps modules imported successfully")
        
        # Test validation
        assert validate_target_simple('127.0.0.1') == True
        assert validate_target_simple('invalid') == False
        print("   ✅ Target validation working")
        
        print("✅ Basic tests passed.")
        
    except Exception as e:
        print(f"⚠️  Warning: Some tests failed: {e}")
        print("   The installation may still work, but please check manually.")


def print_next_steps():
    """Print next steps for the user."""
    print("[8/8] Setup complete!")
    print("\n" + "="*60)
    print("🎉 RedOps-AI has been set up successfully!")
    print("="*60)
    print("\nNext steps:")
    print("1. Edit the .env file with your API keys:")
    print("   - Add your OpenAI API key (OPENAI_API_KEY)")
    print("   - Or add your Anthropic API key (ANTHROPIC_API_KEY)")
    print("\n2. Review and customize config/config.yaml if needed")
    print("\n3. Test the CLI:")
    print("   python3 -m redops.cli.main --help")
    print("\n4. Run a basic scan:")
    print("   python3 -m redops.cli.main scan 127.0.0.1")
    print("\n5. For development, run tests:")
    print("   pytest tests/")
    print("\nFor more information, see README.md")
    print("\n" + "="*60)


def main():
    """Main setup function."""
    print_banner()
    
    try:
        check_python_version()
        check_nmap()
        create_directories()
        install_dependencies()
        setup_environment()
        create_default_config()
        run_tests()
        print_next_steps()
        
    except KeyboardInterrupt:
        print("\n❌ Setup interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed with error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()