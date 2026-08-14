FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
RUN apk add --no-cache softhsm
COPY init.sh /usr/local/bin/init.sh
COPY healthcheck /usr/local/bin/healthcheck
RUN chmod 0755 /usr/local/bin/init.sh /usr/local/bin/healthcheck
ENTRYPOINT ["/usr/local/bin/init.sh"]
