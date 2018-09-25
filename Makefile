OUTPUT_DIR = bin
BINARYNAME = pwned-passwd-parser

deps:
	dep ensure -v

clean:
	rm -rf bin

update-deps:
	if ! [ -d vendor ]; then make deps; fi
	dep ensure -v -update

lint:
	golangci-lint run

build: lint
	CGO_ENABLED=0 go build -o $(OUTPUT_DIR)/$(BINARYNAME) $(LDFLAGS) main.go