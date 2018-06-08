FROM golang:1.10.2

ARG version

WORKDIR /go/src/github.com/skybet/ldap_proxy

COPY . .

RUN VERSION=$version make linux

FROM scratch

COPY --from=0 /go/src/github.com/skybet/ldap_proxy/dist/ldap_proxy-linux-amd64 .

CMD ["/ldap_proxy-linux-amd64"]
