# SYNTHETIC placeholder digest; not a verified or pullable supply-chain receipt.
FROM registry.invalid/approved/python@sha256:0000000000000000000000000000000000000000000000000000000000000000
WORKDIR /srv/atlas
COPY api/ /srv/atlas/api/
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1
# Server binary, TLS terminator and verified image must be supplied before building.
CMD ["/usr/local/bin/approved-wsgi", "api.app:create_app"]
