# RedOps-AI 🚀

**Multi-Agent Penetration Testing Framework**

RedOps-AI is an advanced, AI-powered penetration testing framework that leverages multiple specialized agents to perform comprehensive security assessments. Built with LangChain and LangGraph, it combines the power of large language models with traditional security tools to provide intelligent, automated reconnaissance and analysis.

## ✨ Features

- **🤖 Multi-Agent Architecture**: Specialized agents for different phases of penetration testing
- **🧠 AI-Powered Analysis**: LLM integration for intelligent result interpretation
- **🔍 Comprehensive Reconnaissance**: Advanced Nmap integration with smart scanning strategies
- **📊 Intelligent Reporting**: Automated report generation with risk assessment
- **🎯 Target Validation**: Support for IP addresses, CIDR ranges, and domain names
- **⚡ Flexible CLI**: Easy-to-use command-line interface with multiple output formats
- **🔧 Extensible Design**: Modular architecture for easy tool integration

## 🏗️ Architecture

RedOps-AI uses a multi-agent workflow orchestrated by LangGraph:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Coordinator    │───▶│ Reconnaissance  │───▶│   Analysis      │
│     Agent       │    │     Agent       │    │    Agent        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Reporting     │    │   Tool Manager  │    │  LLM Provider   │
│     Agent       │    │    (Nmap, etc)  │    │ (OpenAI/Claude) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Agent Roles

- **Coordinator Agent**: Orchestrates the entire workflow and manages agent interactions
- **Reconnaissance Agent**: Performs network scanning and service discovery using Nmap
- **Analysis Agent**: Analyzes scan results and identifies potential vulnerabilities
- **Reporting Agent**: Generates comprehensive reports with findings and recommendations

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+**
- **Nmap** (for network scanning)
- **OpenAI API Key** or **Anthropic API Key** (for AI analysis)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/RedOps-AI.git
   cd RedOps-AI
   ```

2. **Install Nmap:**
   ```bash
   # macOS
   brew install nmap
   
   # Ubuntu/Debian
   sudo apt-get install nmap
   
   # CentOS/RHEL
   sudo yum install nmap
   ```

3. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure API Keys:**
   ```bash
   # Create .env file
   cp .env.example .env
   
   # Edit .env and add your API keys
   OPENAI_API_KEY=your_openai_api_key_here
   # OR
   ANTHROPIC_API_KEY=your_anthropic_api_key_here
   ```

### Basic Usage

#### Simple CLI (No Dependencies)

For quick testing without external dependencies:

```bash
# Show help
python3 redops_cli.py --help

# Display banner
python3 redops_cli.py --banner

# Basic scan (requires root for some scan types)
sudo python3 redops_cli.py scan 192.168.1.1

# Scan with different types
sudo python3 redops_cli.py scan example.com --type stealth
sudo python3 redops_cli.py scan 192.168.1.0/24 --type comprehensive

# JSON output
sudo python3 redops_cli.py scan 192.168.1.1 --format json
```

#### Full CLI (With Dependencies)

Once dependencies are installed:

```bash
# Basic reconnaissance scan
python -m redops.cli.main scan 192.168.1.1

# Stealth scan with custom ports
python -m redops.cli.main scan example.com --type stealth --ports 80,443,8080

# Comprehensive scan with timing
python -m redops.cli.main scan 192.168.1.0/24 --type comprehensive --timing 4

# Autonomous mode (AI-powered analysis)
python -m redops.cli.main scan 192.168.1.1 --autonomous

# Batch scanning
python -m redops.cli.main batch targets.txt --output results/
```

## 📋 Command Reference

### Scan Commands

```bash
# Single target scan
redops scan <target> [options]

# Batch scanning
redops batch <target_file> [options]

Options:
  --type {basic,stealth,comprehensive}  Scan type (default: basic)
  --ports PORT_RANGE                    Port specification (default: top 1000)
  --timing {0-5}                        Timing template (default: 3)
  --output FORMAT                       Output format (table/json/summary)
  --autonomous                          Enable AI-powered analysis
  --save FILE                          Save results to file
```

### Target Management

```bash
# Add targets to list
redops target add 192.168.1.1
redops target add example.com
redops target add 10.0.0.0/24

# List targets
redops target list

# Remove target
redops target remove 192.168.1.1
```

### History Management

```bash
# List scan history
redops history list

# Show specific scan
redops history show <scan_id>
```

### Configuration

```bash
# Show current configuration
redops config

# Setup wizard
redops setup
```

## 🔧 Configuration

### Configuration File

RedOps-AI uses YAML configuration files. The default configuration is loaded from `config/config.yaml`:

```yaml
application:
  name: "RedOps-AI"
  version: "1.0.0"
  environment: "development"
  debug: true

logging:
  level: "INFO"
  format: "json"
  file: "logs/redops.log"

tools:
  nmap:
    path: "/usr/bin/nmap"
    default_args: ["-sS", "-O", "-sV"]
    timeout: 300

ai:
  provider: "openai"  # or "anthropic"
  model: "gpt-4"
  temperature: 0.1
  max_tokens: 2000

scanning:
  default_ports: "1-1000"
  timing_template: 3
  max_concurrent: 10
```

### Environment Variables

```bash
# API Keys
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key

# Configuration
REDOPS_CONFIG_PATH=/path/to/config.yaml
REDOPS_LOG_LEVEL=DEBUG
REDOPS_ENVIRONMENT=production
```

## 🧪 Testing

### Run Tests

```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=redops

# Run specific test
python -m pytest tests/test_agents.py
```

### CLI Testing

```bash
# Test basic functionality
python test_cli.py

# Test with simple CLI
python redops_cli.py test
```

## 📁 Project Structure

```
RedOps-AI/
├── redops/                    # Main package
│   ├── agents/               # Agent implementations
│   │   ├── base.py          # Base agent class
│   │   ├── coordinator.py   # Workflow coordinator
│   │   └── reconnaissance.py # Network reconnaissance
│   ├── cli/                 # Command-line interface
│   │   ├── main.py         # Main CLI module
│   │   └── commands.py     # CLI commands
│   ├── core/               # Core functionality
│   │   ├── config.py       # Configuration management
│   │   ├── logging.py      # Logging setup
│   │   ├── validation.py   # Input validation
│   │   └── exceptions.py   # Custom exceptions
│   └── tools/              # External tool integrations
│       ├── __init__.py     # Tool manager
│       └── nmap.py         # Nmap integration
├── config/                 # Configuration files
│   └── config.yaml        # Default configuration
├── tests/                 # Test suite
├── docs/                  # Documentation
├── requirements.txt       # Python dependencies
├── redops_cli.py         # Simple CLI entry point
├── test_cli.py           # CLI test suite
└── README.md             # This file
```

## 🔒 Security Considerations

- **Permissions**: Some scan types require root privileges
- **API Keys**: Store API keys securely using environment variables
- **Network**: Be mindful of network policies and scan targets
- **Rate Limiting**: Respect API rate limits and target resources
- **Legal**: Ensure you have permission to scan target systems

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/your-org/RedOps-AI.git
cd RedOps-AI

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run tests
python -m pytest
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **LangChain** for the AI framework
- **LangGraph** for workflow orchestration
- **Nmap** for network scanning capabilities
- **Click** for the CLI framework
- **Rich** for beautiful terminal output

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/RedOps-AI/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/RedOps-AI/discussions)
- **Documentation**: [Wiki](https://github.com/your-org/RedOps-AI/wiki)

---

**⚠️ Disclaimer**: RedOps-AI is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any systems. The developers are not responsible for any misuse of this tool.
