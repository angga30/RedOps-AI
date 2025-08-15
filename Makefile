# RedOps-AI Makefile
# Convenient commands for development, testing, and deployment

.PHONY: help install install-dev test test-unit test-integration lint format type-check clean setup run docs docker

# Default target
help:
	@echo "RedOps-AI Development Commands"
	@echo "=============================="
	@echo ""
	@echo "Setup and Installation:"
	@echo "  setup          - Run full setup (install deps, create config, etc.)"
	@echo "  install        - Install production dependencies"
	@echo "  install-dev    - Install development dependencies"
	@echo ""
	@echo "Development:"
	@echo "  run            - Run the CLI with help"
	@echo "  run-scan       - Run a test scan on localhost"
	@echo "  format         - Format code with black"
	@echo "  lint           - Run linting with flake8"
	@echo "  type-check     - Run type checking with mypy"
	@echo "  check          - Run all code quality checks"
	@echo ""
	@echo "Testing:"
	@echo "  test           - Run all tests"
	@echo "  test-unit      - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo ""
	@echo "Documentation:"
	@echo "  docs           - Generate documentation"
	@echo "  docs-serve     - Serve documentation locally"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean          - Clean up temporary files"
	@echo "  clean-all      - Clean everything including caches"
	@echo "  update-deps    - Update dependencies"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run in Docker container"

# Setup and Installation
setup:
	@echo "Setting up RedOps-AI development environment..."
	python3 setup.py

install:
	@echo "Installing production dependencies..."
	pip install -r requirements.txt

install-dev: install
	@echo "Installing development dependencies..."
	pip install pytest pytest-asyncio pytest-cov black flake8 mypy pre-commit
	pre-commit install

# Development
run:
	@echo "Running RedOps-AI CLI..."
	python3 -m redops.cli.main --help

run-scan:
	@echo "Running test scan on localhost..."
	python3 -m redops.cli.main scan 127.0.0.1

run-simple:
	@echo "Running simplified CLI..."
	python3 redops_cli.py --help

format:
	@echo "Formatting code with black..."
	black --line-length 88 .
	@echo "Code formatted successfully!"

lint:
	@echo "Running linting with flake8..."
	flake8 --max-line-length 88 --extend-ignore E203,W503 redops/ tests/
	@echo "Linting completed!"

type-check:
	@echo "Running type checking with mypy..."
	mypy redops/ --ignore-missing-imports
	@echo "Type checking completed!"

check: format lint type-check
	@echo "All code quality checks completed!"

# Testing
test:
	@echo "Running all tests..."
	pytest -v

test-unit:
	@echo "Running unit tests..."
	pytest tests/unit/ -v

test-integration:
	@echo "Running integration tests..."
	pytest tests/integration/ -v

test-coverage:
	@echo "Running tests with coverage..."
	pytest --cov=redops --cov-report=html --cov-report=term-missing
	@echo "Coverage report generated in htmlcov/"

test-simple:
	@echo "Running simplified tests..."
	python3 test_cli.py

# Documentation
docs:
	@echo "Generating documentation..."
	@echo "Documentation generation not yet implemented"

docs-serve:
	@echo "Serving documentation locally..."
	@echo "Documentation serving not yet implemented"

# Maintenance
clean:
	@echo "Cleaning temporary files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name "*.tmp" -delete
	find . -type f -name "*.log" -delete
	@echo "Temporary files cleaned!"

clean-all: clean
	@echo "Cleaning all generated files..."
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info/
	rm -rf results/
	rm -rf reports/
	rm -rf logs/
	@echo "All generated files cleaned!"

update-deps:
	@echo "Updating dependencies..."
	pip install --upgrade pip
	pip install --upgrade -r requirements.txt
	@echo "Dependencies updated!"

# Docker
docker-build:
	@echo "Building Docker image..."
	docker build -t redops-ai .

docker-run:
	@echo "Running in Docker container..."
	docker run -it --rm redops-ai

# Security
security-check:
	@echo "Running security checks..."
	pip install safety bandit
	safety check
	bandit -r redops/
	@echo "Security checks completed!"

# Performance
profile:
	@echo "Running performance profiling..."
	python3 -m cProfile -o profile_stats -m redops.cli.main scan 127.0.0.1
	python3 -c "import pstats; p = pstats.Stats('profile_stats'); p.sort_stats('cumulative').print_stats(20)"

# Environment
env-check:
	@echo "Checking environment..."
	@echo "Python version: $$(python3 --version)"
	@echo "Pip version: $$(pip --version)"
	@echo "Nmap version: $$(nmap --version | head -1)"
	@echo "Current directory: $$(pwd)"
	@echo "Environment variables:"
	@env | grep -E '^(REDOPS|OPENAI|ANTHROPIC)' || echo "No RedOps environment variables set"

# Quick development workflow
dev: install-dev check test
	@echo "Development workflow completed!"

# CI/CD simulation
ci: install check test-coverage
	@echo "CI pipeline simulation completed!"

# Release preparation
release-check: clean-all install-dev check test-coverage security-check
	@echo "Release checks completed!"

# Debugging
debug:
	@echo "Running in debug mode..."
	REDOPS_DEBUG=true REDOPS_LOG_LEVEL=DEBUG python3 -m redops.cli.main scan 127.0.0.1

# Show project info
info:
	@echo "RedOps-AI Project Information"
	@echo "============================="
	@echo "Project structure:"
	@find . -type f -name "*.py" | head -20
	@echo "\nTotal Python files: $$(find . -name "*.py" | wc -l)"
	@echo "Total lines of code: $$(find . -name "*.py" -exec wc -l {} + | tail -1)"
	@echo "\nDependencies:"
	@pip list | grep -E '(langchain|click|rich|nmap)' || echo "Core dependencies not installed"

# Development server (if implementing web interface later)
server:
	@echo "Development server not yet implemented"
	@echo "This will be used for web interface in future versions"

# Database operations (if implementing database storage)
db-init:
	@echo "Database initialization not yet implemented"

db-migrate:
	@echo "Database migration not yet implemented"

# Backup and restore
backup:
	@echo "Creating backup of configuration and results..."
	mkdir -p backups/$$(date +%Y%m%d_%H%M%S)
	cp -r config/ backups/$$(date +%Y%m%d_%H%M%S)/ 2>/dev/null || true
	cp -r results/ backups/$$(date +%Y%m%d_%H%M%S)/ 2>/dev/null || true
	cp .env backups/$$(date +%Y%m%d_%H%M%S)/ 2>/dev/null || true
	@echo "Backup created in backups/ directory"

# Show available make targets
targets:
	@echo "Available make targets:"
	@make -qp | awk -F':' '/^[a-zA-Z0-9][^$$#\/\t=]*:([^=]|$$)/ {split($$1,A,/ /);for(i in A)print A[i]}' | sort | uniq