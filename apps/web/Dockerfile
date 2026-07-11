FROM node:22-alpine AS build
WORKDIR /app
COPY apps/web/package.json apps/web/tsconfig.json apps/web/index.html /app/
COPY apps/web/src /app/src
RUN npm install && npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80

