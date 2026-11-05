# CloudShield core API image.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY services ./services
RUN pip install --no-cache-dir --prefix=/install ".[postgres,aws,k8s]"

FROM python:3.12-slim
LABEL org.opencontainers.image.source=https://github.com/aymen-nasri/cloudshield \
      org.opencontainers.image.description="CloudShield core API" \
      org.opencontainers.image.licenses=MIT
RUN useradd --system --uid 10001 --no-create-home cloudshield
COPY --from=build /install /usr/local
COPY runbooks /opt/cloudshield/runbooks
# A named volume mounted here takes this ownership, so the non-root process can archive evidence.
RUN mkdir /evidence && chown 10001 /evidence
ENV CLOUDSHIELD_RUNBOOKS_DIR=/opt/cloudshield/runbooks
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["uvicorn", "core.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
