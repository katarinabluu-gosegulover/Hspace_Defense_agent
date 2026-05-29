FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

COPY defense_agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ARG AGENT_ENTRYPOINT=""
ENV DEFENSE_AGENT_ENTRYPOINT=${AGENT_ENTRYPOINT}

COPY . .

CMD ["python", "-m", "agent_sdk.runner"]
