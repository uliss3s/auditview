.PHONY: build test run clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o auditview .

test:
	go vet ./...
	go test ./...

run: build
	sudo ./auditview

clean:
	rm -f auditview
