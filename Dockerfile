FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the project files
COPY . .

# Install the package and its dependencies
RUN pip install --no-cache-dir .

# Install Playwright and its system dependencies for Chromium
RUN playwright install --with-deps chromium

# Create a volume for reports
VOLUME /app/reports

# Set entrypoint
ENTRYPOINT ["senfoniscan"]
CMD ["--help"]
