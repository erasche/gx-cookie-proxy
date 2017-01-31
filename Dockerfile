FROM alpine:3.4
MAINTAINER Eric Rasche <esr@tamu.edu>
EXPOSE 5000

RUN apk update && \
	apk add curl

ENV GXC_VERSION v0.9.2-2-g4b7ae62
RUN curl -L https://github.com/erasche/gx-cookie-proxy/releases/download/${GXC_VERSION}/gx-cookie-proxy_linux_amd64 > /usr/bin/gx-cookie-proxy && \
	chmod +x /usr/bin/gx-cookie-proxy

ENTRYPOINT ["/usr/bin/gx-cookie-proxy"]
