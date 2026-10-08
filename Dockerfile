FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install ".[vault]" && useradd --uid 10001 --create-home app
USER app
EXPOSE 8000
CMD ["mcp-hub", "serve", "--host", "0.0.0.0", "--port", "8000"]
