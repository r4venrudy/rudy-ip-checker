FROM python:3.12-slim-bookworm
LABEL org.opencontainers.image.source="https://github.com/r4venrudy/rudy-ip-checker" org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt && python -m pip check
COPY main.py raven.png LICENSE ./
COPY rudy_runtime ./rudy_runtime
COPY tests ./tests
RUN python -m unittest discover -s tests -v && useradd --uid 10001 --create-home rudy
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "/app/main.py"]
