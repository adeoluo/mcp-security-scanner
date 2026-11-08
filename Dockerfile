# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/adeoluo/mcp-security-scanner/internal/cli.Version=${VERSION}" \
      -o /out/mcpscan ./cmd/mcpscan

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/mcpscan /usr/local/bin/mcpscan
USER nonroot
EXPOSE 8080
ENTRYPOINT ["mcpscan"]
CMD ["serve", "--addr", ":8080"]
