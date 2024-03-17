# syntax=docker/dockerfile:1
# Build
FROM --platform=linux/amd64 docker.io/golang:1.22-alpine AS builder
WORKDIR /workspace
COPY . .
# We must run with CGO_ENABLED=0 because otherwise the alpine container wont be able to launch it unless we install more packages
# We also must remove the "v" from the TARGETVARIAT since docker takes "v7" while go takes just "7"
RUN CGO_ENABLED=0 go build -o asset-registry

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /workspace/asset-registry ./
EXPOSE 8080
CMD ["./asset-registry"]