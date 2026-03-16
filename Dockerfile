FROM python:3.12-slim

LABEL maintainer="cvemula1"
LABEL description="NHInsight — Non-Human Identity discovery CLI"

WORKDIR /app

# Install all providers
COPY pyproject.toml setup.py README.md LICENSE ./
COPY nhinsight/ nhinsight/
RUN pip install --no-cache-dir ".[all]"

ENTRYPOINT ["nhinsight"]
CMD ["--help"]
