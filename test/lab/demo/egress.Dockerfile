# tt (linux/amd64, built by deploy-infra.sh) in a minimal non-root image.
FROM gcr.io/distroless/static-debian12:nonroot
COPY bin/tt /usr/local/bin/tt
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/tt"]
