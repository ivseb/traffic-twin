# One image with the three Go demo binaries: carrier, loadgen, truthcheck.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY internal ./internal
COPY carrier ./carrier
COPY loadgen ./loadgen
COPY truthcheck ./truthcheck
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./carrier ./loadgen ./truthcheck

FROM alpine:3.20
COPY --from=build /out/ /usr/local/bin/
USER nobody
CMD ["carrier"]
