# Red team round 3: FastAPI (uvicorn) + Python SDK from the init image
# (deploy/images/sdk-python), installed with traffic_twin.install(app).
# Build: test/redteam/frameworks/build_images.sh python
FROM python:3.12.7-slim
RUN pip install --no-cache-dir fastapi==0.115.4 uvicorn==0.32.0
COPY --from=rt3fw-sdk-python:local /sdk/python /tt/sdk/python
WORKDIR /app
COPY test/redteam/frameworks/python/app.py ./
RUN useradd -m -u 10001 app && install -d -o app -g app -m 0700 /var/lib/tt-state
USER app
ENV PYTHONPATH=/tt/sdk/python/site PYTHONUNBUFFERED=1
EXPOSE 8080
# The uvicorn access log is off: it prints paths and queries (the app's own
# log, not the SDK's), which here carry canaries.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
