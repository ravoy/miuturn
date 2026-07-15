FROM debian:bookworm-slim

ARG TARGETARCH=amd64

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY dist/miuturn-linux-${TARGETARCH} /usr/local/bin/miuturn
RUN chmod +x /usr/local/bin/miuturn

COPY miuturn.toml.example ./miuturn.toml

ENV CONFIG=/app/miuturn.toml

ENTRYPOINT ["miuturn"]
