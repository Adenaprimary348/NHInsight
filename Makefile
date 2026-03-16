.PHONY: install dev test lint fix demo scan-aws scan-azure scan-gcp scan-k8s scan-all docker docker-demo clean

install:
	pip install -e .

dev:
	pip install -e ".[all,dev]"

test:
	python3 -m pytest tests/ -v --tb=short

lint:
	python3 -m ruff check nhinsight/ tests/

fix:
	python3 -m ruff check nhinsight/ tests/ --fix

demo:
	python3 -m nhinsight.cli demo

scan-aws:
	python3 -m nhinsight.cli scan --aws

scan-azure:
	python3 -m nhinsight.cli scan --azure

scan-gcp:
	python3 -m nhinsight.cli scan --gcp

scan-k8s:
	python3 -m nhinsight.cli scan --k8s

scan-all:
	python3 -m nhinsight.cli scan --all --attack-paths

docker:
	docker build -t nhinsight .

docker-demo:
	docker run --rm nhinsight demo

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
