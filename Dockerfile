FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY brain ./brain

# Root olmayan kullanıcıyla çalış (en az yetki)
RUN useradd --create-home --uid 10001 beyin && mkdir -p /app/data && chown -R beyin /app
USER beyin

EXPOSE 8080
CMD ["python", "-m", "brain"]
