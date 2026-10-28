# syntax=docker/dockerfile:1
#
# SDK init image for Node.js. The pod webhook (tt injector) runs it as an init
# container: it copies /sdk into the shared emptyDir (/tt/sdk) and exits. The
# application then starts with NODE_OPTIONS="--import /tt/sdk/node/dist/esm/register.js".
#
# Build from the repository root:
#   docker build -f deploy/images/sdk-node/Dockerfile -t ghcr.io/ivseb/traffic-twin/sdk-node:0.1.0 .
#
# Base images are pinned by digest; bump tag and digest together.

FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS build
WORKDIR /src/sdk/node
COPY sdk/node/package.json sdk/node/package-lock.json ./
RUN npm ci --no-audit --no-fund --ignore-scripts
COPY sdk/node/tsconfig.json sdk/node/tsconfig.cjs.json ./
COPY sdk/node/scripts/build.mjs scripts/build.mjs
COPY sdk/node/src src
RUN npm run build

# busybox only for `cp`; musl variant, 4 MiB. No shell is needed at run time.
FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092
LABEL org.opencontainers.image.title="traffic-twin sdk-node (init image)" \
      org.opencontainers.image.source="https://github.com/ivseb/traffic-twin" \
      org.opencontainers.image.licenses="Apache-2.0"
# The SDK has no runtime dependencies: dist/ is everything the application needs.
COPY --from=build /src/sdk/node/dist/ /sdk/node/dist/
USER 65532:65532
ENTRYPOINT ["cp", "-R", "/sdk/.", "/tt/sdk/"]
