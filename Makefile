.PHONY=test

test:
	go test ./...

# generate test coverage profile, print results to stdout
cov:
	go test -coverprofile=coverage.out ./... && \
	  go tool cover -func=coverage.out

# generate test coverage profile, render results as html, show
# in browser
covhtml:
	go test  -coverprofile=coverage.out ./... && \
	  go tool cover -html=coverage.out -o coverage.html && \
	  xdg-open ./coverage.html


vet:
	go vet ./...

staticcheck:
	staticcheck ./...

check:
	go vet ./... && staticcheck ./... && golangci-lint run ./...
# check:
#	go vet ./... && staticcheck ./... && golangci-lint run ./... && govulncheck ./...
