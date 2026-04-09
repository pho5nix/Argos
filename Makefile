# Argos — common commands for local development.
# All commands assume you have Docker, Docker Compose, and Python 3.12.

.PHONY: help install demo stop test hermes lint clean

help:
	@echo "Argos — Alert Investigation Copilot"
	@echo ""
	@echo "Common commands:"
	@echo "  make install   Install Python dependencies (dev + runtime)"
	@echo "  make demo      Start the full local demo stack (Ollama + Presidio + UI)"
	@echo "  make stop      Stop the local demo stack"
	@echo "  make test      Run the unit test suite"
	@echo "  make hermes    Run the Hermes Test (red-team prompt-injection corpus)"
	@echo "  make lint      Run ruff for linting"
	@echo "  make clean     Remove generated files, caches, and volumes"
	@echo ""
	@echo "After 'make demo', open http://localhost:8080 in your browser."

install:
	pip install -e ".[dev]"
	python -m spacy download en_core_web_lg

demo:
	docker compose up --build

stop:
	docker compose down

test:
	pytest -v

hermes:
	python -m redteam.run_hermes_test

lint:
	ruff check argos/ redteam/ tests/ demo/

clean:
	docker compose down -v
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__
	find . -name "*.pyc" -delete
