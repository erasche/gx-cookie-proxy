FROM alpine:3.4
MAINTAINER Eric Rasche <esr@tamu.edu>
EXPOSE 5000

RUN apk update && \
	apk add curl

RUN curl -L https://github.com/erasche/gx-cookie-proxy/releases/download/v0.9.9/gx-cookie-proxy_linux_amd64 > /usr/bin/gx-cookie-proxy && \
	chmod +x /usr/bin/gx-cookie-proxy

ENTRYPOINT ["/usr/bin/gx-cookie-proxy"]
