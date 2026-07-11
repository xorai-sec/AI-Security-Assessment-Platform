FROM node:24-alpine
WORKDIR /worker
COPY workers/promptfoo-worker/package.json /worker/package.json
RUN npm install
COPY workers/promptfoo-worker/server.js /worker/server.js
RUN addgroup -S worker && adduser -S worker -G worker && mkdir -p /artifacts/promptfoo && chown -R worker:worker /worker /artifacts
USER worker
EXPOSE 8095
CMD ["npm", "start"]
