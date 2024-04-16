all: gen

.PHONY : gen

gen: dev

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -extldflags -static"

genqlient:
	cd infrastructure/analytics; go run github.com/Khan/genqlient
