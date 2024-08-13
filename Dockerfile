FROM golang:1-alpine as builder
RUN apk add alpine-sdk libseccomp libseccomp-dev linux-headers

RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN apk add openssl-dev
RUN go build -o seccompagent ./cmd/seccompagent

FROM alpine:latest
RUN apk add libseccomp
RUN apk add openssl
RUN mkdir /certs
COPY certs/ca.crt /certs/ca.crt
COPY certs/client.key /certs/client.key
COPY certs/client.crt /certs/client.crt
COPY certs/server.key /certs/server.key
COPY certs/server.crt /certs/server.crt
COPY --from=builder /build/seccompagent /bin/seccompagent
COPY --from=ghcr.io/spiffe/spire-agent:1.5.1 /opt/spire/bin/spire-agent /bin/spire-agent

CMD ["/bin/seccompagent", "-resolver=kubernetes"]
