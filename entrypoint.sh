#!/bin/bash
set -e

# 1. Czekanie na bazę danych
echo "Czekam na bazę danych PostgreSQL..."
pixi run python -c "
import socket
import time
import os

host = 'db'
port = 5432
max_retries = 30

for i in range(max_retries):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            print('Baza danych jest gotowa!')
            exit(0)
    except Exception:
        pass
    print(f'   ... oczekiwanie ({i+1}/{max_retries})')
    time.sleep(1)
exit(1)
"

# 2. Hard Reset Bazy Danych (Drop & Create)
echo "Czyszczenie i inicjalizacja bazy danych (init_db.py)..."
pixi run db-init

# 3. Start aplikacji
echo "Startuję aplikację..."
exec "$@"