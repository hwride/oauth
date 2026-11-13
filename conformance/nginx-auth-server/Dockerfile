# This is a simple nginx proxy to do https termination for our authorization server,
# which is one of the requirements of the conformance suite tests.

FROM nginx:alpine

# Install the single PEM-formatted extra CA supplied as a BuildKit secret, then install OpenSSL and
# generate a self-signed TLS certificate for host.docker.internal.
# Note this is for development only and not suitable for production.
RUN --mount=type=secret,id=extra_ca,target=/tmp/extra-ca.pem \
  set -eu; \
  cp /tmp/extra-ca.pem /usr/local/share/ca-certificates/extra-ca.crt; \
  update-ca-certificates \
  && apk add --no-cache openssl \
  && openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout /etc/nginx/tls.key \
    -out /etc/nginx/tls.crt \
    -subj "/CN=host.docker.internal" \
    -addext "subjectAltName=DNS:host.docker.internal"

COPY nginx.conf /etc/nginx/nginx.conf
