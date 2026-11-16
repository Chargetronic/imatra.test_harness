# Test charging station of the Imatra test harness.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY station ./station
ENTRYPOINT ["python", "-m", "station"]
