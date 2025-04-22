# execution image
# Use distroless as minimal base image to package the caas-operator binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
# Stage 2: Create the final distroless image
FROM gcr.io/distroless/base-debian11:debug

WORKDIR /

# source path of the binary to put into the image
ARG BINARY_SOURCE_PATH

# copy binary into the image
COPY ${BINARY_SOURCE_PATH} ./auth-operator

USER 65532:65532

# exec binary in image
ENTRYPOINT ["/auth-operator"]
