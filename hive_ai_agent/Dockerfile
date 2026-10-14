FROM python:3.11-slim

WORKDIR /opt/hive_ai_agent

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY hive_ai_agent.py prompt_guard.py configuration.json ./

# Run as an unprivileged user
RUN useradd --create-home agent
USER agent

EXPOSE 8008

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
	CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8008/health')" || exit 1

CMD ["python", "hive_ai_agent.py"]
