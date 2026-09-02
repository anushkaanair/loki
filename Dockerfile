# Two-stage build for the live dashboard deployment.
#
# The dashboard's "launch campaign" flow runs the deterministic simulator
# backend only (no GPU, no HF model download), so the runtime image stays
# small and needs nothing beyond the base Python dependencies.

FROM node:20-slim AS frontend
WORKDIR /app/dashboard
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci
COPY dashboard/ ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml README.md ./
COPY engine ./engine
COPY cli ./cli
COPY campaigns ./campaigns
RUN pip install --no-cache-dir -e .

COPY --from=frontend /app/dashboard/dist ./dashboard/dist

EXPOSE 8008
CMD ["python", "-m", "engine.api.server"]
