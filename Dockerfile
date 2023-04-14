FROM golang:1-alpine as builder
RUN apk add alpine-sdk libseccomp libseccomp-dev

RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN go build -o seccompagent ./cmd/seccompagent

FROM alpine:latest
RUN apk add libseccomp
COPY --from=builder /build/seccompagent /bin/seccompagent
COPY --from=ghcr.io/spiffe/spire-agent:1.5.1 /opt/spire/bin/spire-agent /bin/spire-agent

CMD ["/bin/seccompagent", "-resolver=kubernetes"]
