FROM golang:latest

RUN mkdir /mirroring
WORKDIR /mirroring

COPY ./mirror_log.go ./go.mod ./go.sum ./

RUN go mod download

RUN GO111MODULE=on GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o mirroring .

FROM alpine:latest
WORKDIR ./
COPY --from=0 /mirroring/mirroring ./mirroring
ENTRYPOINT ["./mirroring"]
