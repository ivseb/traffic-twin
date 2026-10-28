FROM node:20-alpine
WORKDIR /app
COPY package.json server.js ./
USER node
EXPOSE 3000
HEALTHCHECK --interval=2s --timeout=2s --retries=15 \
  CMD node -e "fetch('http://localhost:3000/__health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["node", "server.js"]
