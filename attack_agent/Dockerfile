FROM python:3.11-slim

WORKDIR /app

COPY attack_agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ARG AGENT_ENTRYPOINT=""
ENV ATTACK_AGENT_ENTRYPOINT=${AGENT_ENTRYPOINT}

COPY . .

CMD ["python", "-m", "agent_sdk.runner"]
