FROM golang:1.23 AS builder

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 go build -v -o /usr/local/bin/app ./... && chmod 755 /usr/local/bin/app

FROM scratch

COPY --from=builder /usr/local/bin/app /app

ENTRYPOINT ["/app"]