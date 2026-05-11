# Stage 1: Builder
FROM python:3.11-slim AS builder

WORKDIR /app
COPY requirements.txt .

# Install dependencies into a local user directory
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Production Image
FROM python:3.11-slim

# Create a non-root user and group for SOC2 compliance (Least Privilege)
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code
COPY main.py .

# Enforce ownership
RUN chown -R appuser:appgroup /app

# Switch to the non-root user
USER appuser

# Ensure local python binaries are in PATH
ENV PATH=/home/appuser/.local/bin:$PATH
# Prevent python from buffering stdout/stderr (better logging)
ENV PYTHONUNBUFFERED=1 

EXPOSE 15005

# Start the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "15005"]
