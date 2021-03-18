FROM golang:latest

RUN mkdir /mirroring
WORKDIR /mirroring

COPY ./mirror_log.go .
COPY ./go.mod .
COPY ./go.sum .

RUN go mod download

RUN GO111MODULE=on GOOS=linux go build -o mirroring .

FROM ubuntu:latest
WORKDIR /root/
COPY --from=0 /mirroring/mirroring .
CMD ["./mirroring"]
