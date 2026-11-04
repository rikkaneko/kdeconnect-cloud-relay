FROM rust:1.99-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid 10001 relay && useradd --uid 10001 --gid relay --no-create-home relay \
  && install -d -m 0700 -o relay -g relay /var/lib/kdeconnect-cloud-relay
COPY --from=build /build/target/release/kdeconnect-cloud-relay /usr/local/bin/kdeconnect-cloud-relay
USER 10001:10001
ENV RELAY_BIND=0.0.0.0:8443 RELAY_STATE_DIR=/var/lib/kdeconnect-cloud-relay
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/kdeconnect-cloud-relay"]
CMD ["serve"]
