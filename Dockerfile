# Dockerfile (пример)
FROM golang:1.24-alpine AS build

WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . ./
RUN go build -o app

FROM alpine:latest
WORKDIR /root/
COPY --from=build /app/app .

CMD ["./app"]
