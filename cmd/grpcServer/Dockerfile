FROM golang:alpine AS builder
WORKDIR /builder

COPY go.mod ./
COPY go.sum ./
COPY cmd/grpcServer/main.go ./

ADD ./internal ./internal
ADD ./mirroring ./mirroring 

RUN go build -o grpcServer

FROM alpine
WORKDIR /monitor-grpc-service
COPY --from=builder /builder/grpcServer ./
ENTRYPOINT [ "/monitor-grpc-service/grpcServer" ]
