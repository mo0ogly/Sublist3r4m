# ============================================================
# Stage 1: Builder - install Python dependencies into a venv
# ============================================================
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.txt .

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ============================================================
# Stage 2: Runtime - lean image with only what is needed
# ============================================================
FROM python:3.12-slim AS runtime

LABEL maintainer="Sublist3r4m contributors" \
      description="Sublist3r4m - Python subdomain enumeration tool" \
      license="GPL-2.0"

# Carry the virtual-env from the builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create a non-root user
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --create-home appuser

WORKDIR /app

# Copy only the files required at runtime
COPY sublist3r.py            ./sublist3r.py
COPY jarvis_intelligence.py  ./jarvis_intelligence.py
COPY owner_research_engine.py ./owner_research_engine.py
COPY subbrute/               ./subbrute/
COPY config.json.example     ./config.json.example

# Make sure the non-root user owns the working directory
RUN chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["python", "sublist3r.py"]
