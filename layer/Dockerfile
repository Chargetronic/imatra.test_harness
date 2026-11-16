# Test service layer of the Imatra test harness.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /layer ./cmd/layer

FROM alpine:3.20
COPY --from=build /layer /usr/local/bin/layer
ENV LAYER_DIR=/data
VOLUME /data
CMD ["layer", "serve"]
