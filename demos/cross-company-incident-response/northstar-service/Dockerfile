FROM node:22-alpine AS build
WORKDIR /app
COPY demos/cross-company-incident-response/northstar-service/package.json ./
RUN npm install --ignore-scripts
COPY demos/cross-company-incident-response/northstar-service/tsconfig.json ./
COPY demos/cross-company-incident-response/northstar-service/src ./src
RUN npm run build

FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist
ENV PORT=8080 NORTHSTAR_STATE_PATH=/tmp/auths-incident-demo/northstar.json
EXPOSE 8080
CMD ["node", "dist/server.js"]
