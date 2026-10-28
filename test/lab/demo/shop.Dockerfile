# The demo shop (demo/shop, unchanged) with the Node SDK installed from the
# tarball built out of sdk/node (npm pack): the app code is not touched, the
# SDK is loaded with `node --import @traffic-twin/sdk/register`.
FROM node:24-alpine
WORKDIR /app
COPY demo/shop/package.json demo/shop/server.js ./
COPY sdk.tgz /tmp/sdk.tgz
RUN npm install --no-audit --no-fund --omit=dev /tmp/sdk.tgz && rm /tmp/sdk.tgz
USER 1000:1000
EXPOSE 3000
