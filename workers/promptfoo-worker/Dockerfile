FROM node:24-alpine
WORKDIR /worker
ARG WORKER_UID=1000
ARG WORKER_GID=1000
COPY workers/promptfoo-worker/package.json /worker/package.json
RUN npm install
COPY workers/promptfoo-worker/server.js /worker/server.js
RUN mkdir -p /artifacts/promptfoo && chown -R ${WORKER_UID}:${WORKER_GID} /worker /artifacts
USER ${WORKER_UID}:${WORKER_GID}
EXPOSE 8095
CMD ["npm", "start"]
