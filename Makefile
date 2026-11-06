.PHONY: install run test clean lint

install:
	pip install -e .[dev,local]

run:
	python -m src.main

test:
	pytest tests/ -v

lint:
	ruff check src/

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache __pycache__
	find . -name '__pycache__' -exec rm -rf {} +
	find . -name '*.pyc' -delete
