FROM python:3.14-alpine

WORKDIR /app
COPY pyproject.toml README.md ./
COPY snitch ./snitch
RUN pip install --no-cache-dir . && rm -rf /app/*

USER 1000:1000
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=1m --timeout=5s \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"

ENTRYPOINT ["snitch"]
CMD ["serve"]
