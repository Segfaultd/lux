.PHONY: build test coverage run clean

build:
	go build -trimpath -ldflags="-s -w" -o lux ./cmd/lux

test:
	go test ./...

coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

run:
	go run ./cmd/lux

clean:
	go clean
	rm -f lux
