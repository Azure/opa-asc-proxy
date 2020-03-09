FROM golang:1.13.4-alpine as builder
RUN apk add --update make
ENV PATH /go/bin:/usr/local/go/bin:$PATH
ENV GOPATH /go
COPY . /go/src/github.com/Azure/securitycenter-opa
WORKDIR /go/src/github.com/Azure/securitycenter-opa
ARG IMAGE_VERSION=0.0.1
RUN make build

FROM alpine:3.10.3
RUN apk update && apk add --no-cache \
    bash \
    curl \
    jq
COPY --from=builder /go/src/github.com/Azure/securitycenter-opa/securitycenter-opa /bin/
COPY getimagesha.sh /
RUN chmod a+x /bin/securitycenter-opa
RUN chmod a+x /getimagesha.sh

ENTRYPOINT ["/bin/securitycenter-opa"]
