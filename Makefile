.PHONY=test

test:
	go test ./...

vet:
	go vet ./...

staticcheck:
	staticcheck ./...
