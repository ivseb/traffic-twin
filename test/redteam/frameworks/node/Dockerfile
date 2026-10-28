# Red team round 3: Express + Node SDK, zero-code (NODE_OPTIONS --import, as the injector does).
# Build: test/redteam/frameworks/build_images.sh node   (builds rt3fw-sdk-node:local first)
FROM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53
WORKDIR /app
COPY test/redteam/frameworks/node/package.json ./
RUN npm install --no-audit --no-fund --omit=dev --ignore-scripts
COPY test/redteam/frameworks/node/app.js ./
COPY --from=rt3fw-sdk-node:local /sdk/node /tt/sdk/node
RUN install -d -o node -g node -m 0700 /var/lib/tt-state
USER node
ENV NODE_OPTIONS="--import /tt/sdk/node/dist/esm/register.js"
EXPOSE 8080
CMD ["node", "app.js"]
