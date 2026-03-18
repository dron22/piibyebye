## 2026-03-18 Upgrade spaCy to 3.8 for Python 3.13 support

- `pyproject.toml`: Bumped `spacy>=3.8` and updated all language model wheel URLs from `3.7.0` to `3.8.0`. spaCy 3.7.x has no pre-built wheels for Python 3.13, causing source builds to fail when `python-dev` headers are absent.
