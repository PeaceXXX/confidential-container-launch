BIN := coco-launch

.PHONY: build test vet fmt clean

build:
	go build -o $(BIN) ./cmd/coco-launch

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

clean:
	rm -f $(BIN)
