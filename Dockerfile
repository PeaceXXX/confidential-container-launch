# syntax=docker/dockerfile:1
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -o /out/coco-launch ./cmd/coco-launch

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/coco-launch /usr/local/bin/coco-launch
ENTRYPOINT ["coco-launch"]
CMD ["inspect", "--help"]
