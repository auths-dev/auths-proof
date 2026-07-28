FROM nginxinc/nginx-unprivileged:1.29-alpine

ARG COLOR
ARG LABEL
USER root
COPY index.html.template /usr/share/nginx/html/index.html.template
RUN sed -e "s/{{COLOR}}/${COLOR}/g" -e "s/{{LABEL}}/${LABEL}/g" \
      /usr/share/nginx/html/index.html.template \
      > /usr/share/nginx/html/index.html \
    && rm /usr/share/nginx/html/index.html.template \
    && chown 101:101 /usr/share/nginx/html/index.html
USER 101
