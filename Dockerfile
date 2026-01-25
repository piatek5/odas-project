FROM ubuntu:22.04

# Zmienne środowiskowe dla Pixi
ENV PIXI_HOME="/root/.pixi"
ENV PATH="$PIXI_HOME/bin:$PATH"

ENV PYTHONUNBUFFERED=1

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Instalacja Pixi
RUN curl -fsSL https://pixi.sh/install.sh | bash

WORKDIR /app

COPY pyproject.toml pixi.lock ./

RUN pixi install --locked

COPY . .

EXPOSE 5000

CMD ["pixi", "run", "server"]