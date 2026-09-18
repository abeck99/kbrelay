# kbrelay web gateway — a browser keyboard that types into your receivers through the relay.
# Build:  docker build -t kbrelay-gateway .
# See docker-compose.yml and the README for configuration.
FROM python:3.12-slim

RUN pip install --no-cache-dir cryptography aiohttp bcrypt

WORKDIR /app
COPY kbrelay_common.py gateway.py /app/

# Non-root: create a user and a config dir you mount your key + receiver .pub files into.
RUN useradd --system --create-home --uid 10001 kbgw && mkdir /config && chown kbgw /config
USER kbgw

# The web port (override with GATEWAY_PORT and the published port in compose).
EXPOSE 8384

ENTRYPOINT ["python3", "gateway.py"]
CMD ["run"]
