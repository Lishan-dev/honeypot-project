FROM python:3.12-slim

# Run as an unprivileged user -- even inside an isolated container,
# there is no reason this process needs root.
RUN useradd --create-home --shell /bin/bash honeypot
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/data && chown -R honeypot:honeypot /app

USER honeypot
ENV PYTHONUNBUFFERED=1

CMD ["python3", "-m", "honeypot.service"]
