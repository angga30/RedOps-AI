# Contributing to RedOps-AI

Thank you for your interest in contributing to RedOps-AI! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Code Style](#code-style)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Security](#security)

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow:

- **Be respectful**: Treat everyone with respect and kindness
- **Be inclusive**: Welcome newcomers and help them get started
- **Be collaborative**: Work together to improve the project
- **Be professional**: Keep discussions focused and constructive
- **Be ethical**: Use this tool responsibly and only for authorized testing

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Nmap installed and accessible in PATH
- Git for version control
- A text editor or IDE

### Development Setup

1. **Fork the repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/RedOps-AI.git
   cd RedOps-AI
   ```

2. **Set up the development environment**
   ```bash
   # Run the setup script
   python3 setup.py
   
   # Or manually:
   pip install -r requirements.txt
   cp .env.example .env
   # Edit .env with your API keys
   ```

3. **Install development dependencies**
   ```bash
   pip install -r requirements.txt
   pip install pre-commit
   pre-commit install
   ```

4. **Verify installation**
   ```bash
   python3 -m redops.cli.main --help
   pytest tests/
   ```

## Contributing Guidelines

### Types of Contributions

We welcome various types of contributions:

- **Bug fixes**: Fix issues and improve stability
- **New features**: Add new scanning capabilities or AI agents
- **Documentation**: Improve docs, examples, and tutorials
- **Testing**: Add tests and improve test coverage
- **Performance**: Optimize code and improve efficiency
- **Security**: Enhance security features and practices

### Before You Start

1. **Check existing issues**: Look for related issues or discussions
2. **Create an issue**: For new features or major changes, create an issue first
3. **Discuss your approach**: Get feedback before starting significant work
4. **Keep it focused**: Make one change per pull request

## Code Style

### Python Code Style

We follow PEP 8 with some modifications:

```python
# Use Black for formatting
black --line-length 88 .

# Use flake8 for linting
flake8 --max-line-length 88 --extend-ignore E203,W503

# Use mypy for type checking
mypy redops/
```

### Code Organization

- **Keep files under 300 lines**: Split large files into modules
- **Use descriptive names**: Functions, classes, and variables should be clear
- **Add docstrings**: Document all public functions and classes
- **Type hints**: Use type annotations for function parameters and returns
- **Error handling**: Implement proper exception handling

### Example Code Structure

```python
"""Module docstring describing the purpose."""

from typing import List, Optional, Dict, Any
import logging

from redops.core.exceptions import RedOpsError


logger = logging.getLogger(__name__)


class ExampleClass:
    """Example class with proper documentation.
    
    Args:
        param1: Description of parameter
        param2: Optional parameter with default
    """
    
    def __init__(self, param1: str, param2: Optional[int] = None):
        self.param1 = param1
        self.param2 = param2 or 0
    
    def example_method(self, data: List[str]) -> Dict[str, Any]:
        """Example method with type hints and documentation.
        
        Args:
            data: List of strings to process
            
        Returns:
            Dictionary containing processed results
            
        Raises:
            RedOpsError: If processing fails
        """
        try:
            result = {"processed": len(data)}
            logger.info(f"Processed {len(data)} items")
            return result
        except Exception as e:
            logger.error(f"Processing failed: {e}")
            raise RedOpsError(f"Failed to process data: {e}") from e
```

## Testing

### Test Structure

```
tests/
├── unit/                 # Unit tests
│   ├── test_config.py
│   ├── test_validation.py
│   └── test_agents.py
├── integration/          # Integration tests
│   ├── test_cli.py
│   └── test_workflows.py
└── fixtures/             # Test data and fixtures
    ├── config_samples.yaml
    └── nmap_outputs.xml
```

### Writing Tests

```python
import pytest
from unittest.mock import Mock, patch

from redops.core.validation import validate_target
from redops.core.exceptions import ValidationError


class TestValidation:
    """Test cases for target validation."""
    
    def test_valid_ip_address(self):
        """Test validation of valid IP addresses."""
        assert validate_target("192.168.1.1") is True
        assert validate_target("127.0.0.1") is True
    
    def test_invalid_ip_address(self):
        """Test validation of invalid IP addresses."""
        with pytest.raises(ValidationError):
            validate_target("256.256.256.256")
    
    @patch('redops.tools.nmap.NmapScanner')
    def test_scan_with_mock(self, mock_scanner):
        """Test scanning with mocked dependencies."""
        mock_scanner.return_value.scan.return_value = {"status": "success"}
        # Test implementation
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=redops --cov-report=html

# Run specific test file
pytest tests/unit/test_validation.py

# Run tests with verbose output
pytest -v
```

## Documentation

### Docstring Format

Use Google-style docstrings:

```python
def example_function(param1: str, param2: int = 0) -> bool:
    """Brief description of the function.
    
    Longer description if needed. Explain the purpose,
    behavior, and any important details.
    
    Args:
        param1: Description of the first parameter.
        param2: Description of the second parameter. Defaults to 0.
    
    Returns:
        Description of the return value.
    
    Raises:
        ValueError: If param1 is empty.
        RedOpsError: If operation fails.
    
    Example:
        >>> result = example_function("test", 5)
        >>> print(result)
        True
    """
    pass
```

### README Updates

When adding new features:

1. Update the feature list in README.md
2. Add usage examples
3. Update installation instructions if needed
4. Add any new configuration options

## Pull Request Process

### Before Submitting

1. **Test your changes**
   ```bash
   pytest
   python3 -m redops.cli.main --help
   ```

2. **Check code style**
   ```bash
   black --check .
   flake8
   mypy redops/
   ```

3. **Update documentation**
   - Add docstrings to new functions
   - Update README.md if needed
   - Add examples for new features

4. **Write tests**
   - Add unit tests for new functions
   - Add integration tests for new features
   - Ensure good test coverage

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Other (please describe)

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed
- [ ] All tests pass

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
```

### Review Process

1. **Automated checks**: CI/CD will run tests and style checks
2. **Code review**: Maintainers will review your code
3. **Feedback**: Address any requested changes
4. **Approval**: Once approved, your PR will be merged

## Issue Reporting

### Bug Reports

When reporting bugs, include:

- **Environment**: OS, Python version, RedOps-AI version
- **Steps to reproduce**: Clear, step-by-step instructions
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Error messages**: Full error messages and stack traces
- **Configuration**: Relevant config files (remove sensitive data)

### Feature Requests

When requesting features:

- **Use case**: Describe the problem you're trying to solve
- **Proposed solution**: Your idea for how to solve it
- **Alternatives**: Other solutions you've considered
- **Additional context**: Any other relevant information

## Security

### Security Issues

**DO NOT** report security vulnerabilities in public issues.

Instead:
1. Email security issues to the maintainers
2. Include detailed information about the vulnerability
3. Allow time for the issue to be addressed before disclosure

### Security Guidelines

- **Responsible use**: Only use RedOps-AI on systems you own or have permission to test
- **Data protection**: Don't log or store sensitive information
- **API keys**: Never commit API keys or secrets to the repository
- **Input validation**: Always validate user inputs
- **Error handling**: Don't expose sensitive information in error messages

## Development Tips

### Debugging

```bash
# Enable debug logging
export REDOPS_DEBUG=true
export REDOPS_LOG_LEVEL=DEBUG

# Run with verbose output
python3 -m redops.cli.main --verbose scan 127.0.0.1
```

### Testing with Mock Data

```bash
# Use mock AI responses
export DEV_MOCK_AI=true

# Use mock Nmap output
export DEV_MOCK_NMAP=true
```

### Performance Profiling

```python
import cProfile
import pstats

# Profile your code
cProfile.run('your_function()', 'profile_stats')
stats = pstats.Stats('profile_stats')
stats.sort_stats('cumulative').print_stats(10)
```

## Getting Help

- **Documentation**: Check README.md and code comments
- **Issues**: Search existing issues for similar problems
- **Discussions**: Use GitHub Discussions for questions
- **Code review**: Ask for feedback on your approach

## Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes for significant contributions
- GitHub contributor statistics

Thank you for contributing to RedOps-AI! 🚀