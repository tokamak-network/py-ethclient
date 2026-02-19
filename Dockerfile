FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    libsnappy-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
RUN pip3 install --break-system-packages -e ".[dev]" 2>/dev/null || true

COPY . .
RUN pip3 install --break-system-packages -e ".[dev]"

EXPOSE 30303/tcp 30303/udp 8545/tcp 8551/tcp 6060/tcp

ENTRYPOINT ["python3", "-m", "ethclient.main"]
CMD ["--network", "mainnet"]
