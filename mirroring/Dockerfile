FROM golang:latest

RUN mkdir /mirroring
WORKDIR /mirroring

COPY ./mirror_log.go ./go.mod ./go.sum ./

RUN go mod download

RUN GO111MODULE=on GOOS=linux go build -o mirroring .

from ubuntu:latest
WORKDIR /root/
COPY --from=0 /mirroring/mirroring .
RUN apt-get -y update && apt-get -y upgrade ca-certificates
CMD ["./mirroring"]
