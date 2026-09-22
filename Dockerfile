FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    HOST=0.0.0.0 \
    PORT=8443

WORKDIR /opt/crypto-chat

# Copiar solo entradas necesarias evita incluir accidentalmente .env, claves,
# bases de datos, backups o entornos virtuales en la imagen.
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser \
    && mkdir -p data logs backups certs \
    && chown -R appuser:appuser /opt/crypto-chat \
    && chmod 700 /opt/crypto-chat/data /opt/crypto-chat/logs /opt/crypto-chat/backups /opt/crypto-chat/certs

COPY app ./app
COPY frontend ./frontend
RUN chown -R appuser:appuser /opt/crypto-chat/app /opt/crypto-chat/frontend

USER appuser
EXPOSE 8443

# APP_START_COMMAND permite conectar el entrypoint real del backend cuando se
# use otro servidor ASGI/WSGI. El valor del compose arranca FastAPI.
CMD ["sh", "-c", "exec ${APP_START_COMMAND:-uvicorn app.main:app --host ${HOST:-0.0.0.0} --port ${PORT:-8443}}"]
