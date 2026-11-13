# SPDX-License-Identifier: GPL-3.0-only
# The helper is one static program in an otherwise empty image: no shell, nothing else to attack.
FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/helper . && mkdir /out/data

FROM scratch
COPY --from=build /out/helper /helper
# Owned by the unprivileged user, so the volume mounted here is too.
COPY --from=build --chown=65534:65534 /out/data /data
USER 65534:65534
ENTRYPOINT ["/helper"]
CMD ["serve"]
