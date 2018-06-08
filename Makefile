
BINARY=ldap_proxy
GOARCH = amd64
VERSION?=$(shell git describe --tags `git rev-list --tags --max-count=1`)
COMMIT=$(shell git rev-parse HEAD)
BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
BUILD_DIR=dist

# Setup the -ldflags option for go build here, interpolate the variable values
LDFLAGS = -ldflags "-X main.VERSION=${VERSION} -X main.COMMIT=${COMMIT} -X main.BRANCH=${BRANCH}"

test:
	GOMAXPROCS=4 go test -timeout 60s -race ./...

linux:
	GOOS=linux GOARCH=${GOARCH} go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY}-linux-${GOARCH}

darwin:
	GOOS=darwin GOARCH=${GOARCH} go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY}-linux-${GOARCH}

release:
	docker build --build-arg version=${VERSION} -t ldap_proxy:${VERSION} .
	docker create --name release ldap_proxy:${VERSION}
	docker cp release:/ldap_proxy-linux-amd64 .
	docker rm release

fmt:
	go fmt $$(go list ./... | grep -v /vendor/)

.PHONY: test linux darwin fmt release
