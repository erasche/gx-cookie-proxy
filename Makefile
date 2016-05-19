SRC := $(wildcard *.go)
TARGET := gx-cookie-proxy

all: $(TARGET)

$(TARGET): $(SRC)
	go build -o $@

clean:
	$(RM) $(TARGET)

.PHONY: clean
