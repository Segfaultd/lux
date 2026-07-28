FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/lux ./cmd/lux

FROM scratch
COPY --from=build /out/lux /lux
VOLUME ["/data"]
EXPOSE 1234 8080
ENV LUX_DATABASE=/data/lux.db
ENTRYPOINT ["/lux"]
