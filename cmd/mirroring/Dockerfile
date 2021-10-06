FROM golang:1.16-alpine

WORKDIR /build

COPY go.mod ./
COPY go.sum ./

RUN mkdir mirroring
COPY ./mirroring/*.go ./mirroring
COPY ./cmd/mirroring/main.go ./

RUN go build -o /mirroring

ENTRYPOINT [ "/mirroring" ]