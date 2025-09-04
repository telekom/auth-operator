# Use distroless as minimal base image to package the auth-operator binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static-debian12

WORKDIR /

ARG BINARY_SOURCE_PATH
COPY ${BINARY_SOURCE_PATH} ./auth-operator
USER 65532:65532
ENTRYPOINT ["/auth-operator"]
