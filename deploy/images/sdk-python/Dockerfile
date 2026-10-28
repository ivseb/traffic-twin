# syntax=docker/dockerfile:1
#
# SDK init image for Python (>= 3.9). The SDK is pure Python with no
# dependencies, so the image only carries the sources. The injector sets
#   PYTHONPATH=/tt/sdk/python/bootstrap:/tt/sdk/python/site[:<existing>]
# and Python imports bootstrap/sitecustomize.py at start-up, which chains to
# the application's own sitecustomize and then starts the agent.
#
# Build from the repository root:
#   docker build -f deploy/images/sdk-python/Dockerfile -t ghcr.io/ivseb/traffic-twin/sdk-python:0.1.1 .
#
# Base image is pinned by digest; bump tag and digest together.

FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092
LABEL org.opencontainers.image.title="traffic-twin sdk-python (init image)" \
      org.opencontainers.image.source="https://github.com/ivseb/traffic-twin" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY sdk/python/src/traffic_twin/ /sdk/python/site/traffic_twin/
COPY sdk/python/src/traffic_twin/bootstrap/sitecustomize.py /sdk/python/bootstrap/sitecustomize.py
USER 65532:65532
ENTRYPOINT ["cp", "-R", "/sdk/.", "/tt/sdk/"]
