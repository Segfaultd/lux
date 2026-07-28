FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/lux ./cmd/lux

FROM alpine:3.23 AS certificates
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=build /out/lux /lux
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
EXPOSE 1234 8080
ENTRYPOINT ["/lux"]
