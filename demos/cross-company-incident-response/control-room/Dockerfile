FROM node:22-alpine AS build
ARG AUTHS_INCIDENT_AGENT_API=http://localhost:7103
ENV AUTHS_INCIDENT_AGENT_API=$AUTHS_INCIDENT_AGENT_API
WORKDIR /src
COPY bindings/typescript ./bindings/typescript
COPY demos/cross-company-incident-response/control-room ./demos/cross-company-incident-response/control-room
WORKDIR /src/demos/cross-company-incident-response/control-room
RUN npm install --ignore-scripts && npm run build

FROM nginx:1.27-alpine
COPY --from=build /src/demos/cross-company-incident-response/control-room/public /usr/share/nginx/html
EXPOSE 80
