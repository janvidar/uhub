# Pin the base image to a specific Alpine release *by digest* so the build is
# reproducible and does not silently move to a new base. To bump: pick a new
# version and get its multi-arch index digest with
#   docker buildx imagetools inspect alpine:<version>
# then update both values below.
ARG ALPINE_VERSION=3.22
ARG ALPINE_DIGEST=sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

FROM alpine:${ALPINE_VERSION}@${ALPINE_DIGEST} AS builder
RUN apk update && apk upgrade && apk add --no-cache bash util-linux cmake make gcc git sqlite-dev openssl-dev git build-base
WORKDIR /app
COPY . .
RUN cmake -S . -B build && cmake --build build -j
RUN sed -i 's/\/usr\/lib\/uhub\//\/libs\//g' ./doc/*.conf && \
sed -i 's/\/usr\/lib\/uhub\//\/libs\//g' ./doc/rules.txt && \
sed -i 's/\/etc\/uhub\//\/conf\//g' ./doc/*.conf && \
sed -i 's/\/etc\/uhub\//\/conf\//g' ./doc/rules.txt && \
sed -i 's/\/var\/lib\/uhub\/seed/\/seed/g' ./doc/uhub-seeder.conf && \
sed -i 's/^# seed_cache_dir = /seed_cache_dir = /' ./doc/uhub-seeder.conf && \
echo 'Welcome to uhub' > ./doc/motd.txt

FROM alpine:${ALPINE_VERSION}@${ALPINE_DIGEST}
# Runtime shared libraries only -- the -dev packages and build tools belong to
# the builder stage, not the shipped image.
RUN apk update && apk upgrade && apk add --no-cache bash util-linux libssl3 libcrypto3 sqlite-libs
WORKDIR /app
COPY --from=builder /app/build/uhub .
# uhub-seeder ships in the same image but is NOT what the image runs. It is a
# separate process -- that separation is the reason the seed cache was split
# out of the hub, and running both under one entrypoint would throw it away: a
# seeder that wedges on a full disk or a hostile file would take the hub down
# with it. One image, two containers:
#
#   docker run -p 1511:1511 <image>                            # the hub
#   docker run -p 1512:1512 --entrypoint ./uhub-seeder <image> \
#       -c /conf/uhub-seeder.conf                              # the seed cache
#
# The seeder needs its own published port (seed_client_port, 1512 by default)
# and a registered bot account on the hub; it does not read uhub.conf. Mount a
# volume at /seed to keep the cache across container restarts, and edit
# /conf/uhub-seeder.conf -- the shipped one has a placeholder password and will
# not log in.
COPY --from=builder /app/build/uhub-seeder .
COPY --from=builder /app/doc/plugins.conf /app/doc/uhub.conf /app/doc/users.conf /app/doc/rules.txt /app/doc/motd.txt /app/doc/uhub-seeder.conf /conf/
COPY --from=builder /app/build/*.so /libs/

# Run as an unprivileged user rather than root. The default server_port (1511)
# is above 1024, so no privileged-port capability is required. If you configure
# a port below 1024, grant CAP_NET_BIND_SERVICE at run time
# (docker run --cap-add=NET_BIND_SERVICE ...) instead of reverting to root.
# /seed is the seed cache directory (see the note above); the seeder creates it
# with mode 0700 but does not create parents, so it is made here.
RUN addgroup -S uhub && adduser -S -G uhub -H -h /app uhub && \
	mkdir -p /seed && \
	chown -R uhub:uhub /app /conf /libs /seed

USER uhub

ENTRYPOINT ["./uhub"]
CMD ["-c","/conf/uhub.conf"]
