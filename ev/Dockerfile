# Test EV: Josev (SwitchEV iso15118), unmodified; EXI codec runs on Java.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends default-jre-headless iproute2 \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir iso15118==0.31.2
WORKDIR /ev
COPY evcc_config.json entrypoint.sh ./
ENV NETWORK_INTERFACE=eth0 PKI_PATH=/ev/pki/ EVCC_CONFIG_PATH=/ev/evcc_config.json LOG_LEVEL=INFO
ENTRYPOINT ["sh", "/ev/entrypoint.sh"]
