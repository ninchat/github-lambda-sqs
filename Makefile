build:
	GOOS=linux go build -o handler .
	zip handler.zip handler

clean:
	rm -f handler.zip handler

.PHONY: build clean
