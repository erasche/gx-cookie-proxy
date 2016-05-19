SRC := $(wildcard *.go)
TARGET := gx-cookie-proxy

deps:
	go get github.com/Masterminds/glide/...
	go install github.com/Masterminds/glide/...
	glide install

all: $(TARGET) deps

$(TARGET): $(SRC)
	go build -o $@

clean:
	$(RM) $(TARGET)

.PHONY: clean
