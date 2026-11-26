# Disposable public-dependency fixture; not a production egress service.
ARG AGENT_IMAGE=goldenhoop-agent:test
FROM ${AGENT_IMAGE}
COPY --from=goldenhoop-egress:test /usr/local/bin/goldenhoop-egress /usr/local/libexec/goldenhoop-egress
LABEL dev.goldenhoop.fixture="network-interop"
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=3 update \
    && apt-get -o Acquire::Retries=3 install -y --no-install-recommends nftables iptables iproute2 conntrack openssl \
    && rm -rf /var/lib/apt/lists/*
