FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy

WORKDIR /app/backend
RUN apt-get update && apt-get install -y --no-install-recommends openssl zip \
    && apt-get clean
RUN pip install --no-cache-dir uv==0.11.9
COPY backend/.python-version backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen
COPY backend/ ./
COPY control-packs/ /app/control-packs/
COPY schemas/ /app/schemas/
COPY scripts/create-sha-agent-profile-package.sh scripts/sha-agent-package.py /app/scripts/
EXPOSE 8010
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8010"]
