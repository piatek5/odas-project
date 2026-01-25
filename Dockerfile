FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 odas_user && \
    useradd -m -u 1000 -g odas_user -s /bin/bash odas_user

ENV PIXI_HOME="/home/odas_user/.pixi"
ENV PATH="$PIXI_HOME/bin:$PATH"

# Instalacja Pixi
RUN curl -fsSL https://pixi.sh/install.sh | bash

WORKDIR /app

COPY pyproject.toml pixi.lock ./

RUN pixi install --locked

COPY . .

RUN chown -R odas_user:odas_user /app
RUN chown -R odas_user:odas_user /home/odas_user

USER odas_user

CMD ["pixi", "run", "server"]