FROM python:3.11-slim

# Устанавливаем только Docker CLI
RUN apt-get update && apt-get install -y docker.io openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY vpn_bot.py .
RUN pip install pyTelegramBotAPI qrcode[pil]

ENV PYTHONUNBUFFERED=1
CMD ["python", "vpn_bot.py"]
