FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

ARG VERSION=dev
ARG REVISION=unknown
ARG TARGETOS
ARG TARGETARCH
ENV GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -tags timetzdata -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /threat-bot ./cmd/threat-bot \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && mkdir -p /runtime/etc /runtime/app /runtime/data \
    && printf 'threat-bot:x:1000:1000::/app:/sbin/nologin\n' > /runtime/etc/passwd \
    && printf 'threat-bot:x:1000:\n' > /runtime/etc/group \
    && chown 1000:1000 /runtime/data

FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/CraftedSignal/threat-bot" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="AGPL-3.0"
COPY --from=builder /runtime/ /
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chmod=755 /threat-bot /app/threat-bot
COPY LICENSE NOTICE.md /usr/share/licenses/threat-bot/
COPY LICENSES /usr/share/licenses/threat-bot/LICENSES/
WORKDIR /app
USER 1000:1000
ENTRYPOINT ["/app/threat-bot"]
CMD ["-config=/app/config.yaml", "run"]
