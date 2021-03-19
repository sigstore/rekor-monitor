FROM golang:latest

RUN mkdir /mirroring
RUN apt-get install curl
RUN apt-get install openssl
WORKDIR /mirroring

COPY ./mirror_log.go .
COPY ./go.mod .
COPY ./go.sum .

RUN go mod download

RUN GO111MODULE=on GOOS=linux go build -o mirroring .

from ubuntu:latest
WORKDIR /root/
COPY --from=0 /mirroring/mirroring .
RUN apt-get -y update && apt-get -y upgrade ca-certificates
CMD ["./mirroring"]
