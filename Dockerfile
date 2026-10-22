# syntax=docker/dockerfile:1.12
#
# mongo-express â€” minimal production image (Chainguard / Wolfi).
#
# The runtime contains exactly the Chainguard/Wolfi package versions of the
# pinned cgr.dev/chainguard/node image (Node.js, glibc, OpenSSL, ICU,
# dumb-init, CA bundle), minus its shell (busybox) and package managers
# (npm, node-gyp). No shell, no package manager, no compilers.
#
# The debug variant (Dockerfile.debug) is built from the same package
# versions plus troubleshooting tools, so both behave identically.
#
# Build:  docker buildx build --platform linux/amd64,linux/arm64 -t <image>:<tag> .
# Run as any UID with GID 0 (OpenShift restricted SCC compatible); the only
# writable path needed is /tmp.

ARG NODE_DEV_IMAGE=cgr.dev/chainguard/node:latest-dev@sha256:8e34ebb063dd6af4232c01466eb3813dc94ff68d06ed624652830427e032d64b
ARG NODE_IMAGE=cgr.dev/chainguard/node:latest@sha256:6ec35d87faf19dab94214bd8ccd38785a72cf3de02946044a196df1689311376
ARG WOLFI_IMAGE=cgr.dev/chainguard/wolfi-base:latest@sha256:81211e15a86ea1d5357f284482af45730c51de45eaf10ad9ce205d6bfc2df323

# ------------------------------------------------------------- application
# Pure JavaScript: built once on the build platform for every target.
FROM --platform=$BUILDPLATFORM ${NODE_DEV_IMAGE} AS build
# Build argument for enabling OIDC support
ARG ENABLE_OIDC=false
# Test-only binaries are not needed to compile the production application.
ENV CYPRESS_INSTALL_BINARY=0 \
    MONGOMS_DISABLE_POSTINSTALL=1 \
    YARN_ENABLE_GLOBAL_CACHE=false \
    YARN_CACHE_FOLDER=/yarn-cache
# Throwaway build stage: root only writes the build directory.
# hadolint ignore=DL3002
USER root
WORKDIR /dockerbuild
COPY . .
SHELL ["/bin/sh", "-o", "pipefail", "-c"]
# pipefail is set via SHELL (busybox sh supports it; hadolint only recognises bash/ash).
# hadolint ignore=DL4006
RUN --mount=type=cache,target=/yarn-cache,sharing=locked \
    set -eu; \
    yarn() { node .yarn/releases/yarn-4.12.0.cjs "$@"; }; \
    if [ "$ENABLE_OIDC" = "true" ]; then \
      node -e 'const fs=require("fs");const p=JSON.parse(fs.readFileSync("package.json"));p.dependencies["express-openid-connect"]="^2.19.2";if(p.peerDependencies)delete p.peerDependencies["express-openid-connect"];if(p.peerDependenciesMeta)delete p.peerDependenciesMeta["express-openid-connect"];fs.writeFileSync("package.json",JSON.stringify(p,null,2)+"\n")'; \
      yarn install; \
    else \
      yarn install --immutable; \
    fi; \
    yarn build; \
    yarn workspaces focus --production; \
    rm -rf /dockerbuild/lib/scripts; \
    # The image is assembled for several CPU architectures from this one build,
    # which is only correct while production dependencies are pure JavaScript.
    if find node_modules -name '*.node' | grep -q .; then \
      echo "native addons found in production dependencies:"; find node_modules -name '*.node'; exit 1; \
    fi

# ------------------------------------------------------- runtime packages
# The pinned Chainguard node image is used only as the package manifest.
FROM ${NODE_IMAGE} AS nodebase

FROM --platform=$BUILDPLATFORM ${WOLFI_IMAGE} AS rootfs
ARG TARGETARCH
COPY --from=nodebase /usr/lib/apk/db/installed /tmp/base-installed
SHELL ["/bin/sh", "-o", "pipefail", "-c"]
# Installs, for the target architecture and without emulation, the exact
# package versions of the Chainguard node image except busybox/npm/node-gyp.
# hadolint ignore=DL3018,DL4006,SC2086
RUN set -eu; \
    case "${TARGETARCH}" in amd64) arch=x86_64 ;; arm64) arch=aarch64 ;; *) echo "unsupported ${TARGETARCH}"; exit 1 ;; esac; \
    pkgs="$(awk '/^P:/{p=substr($0,3)} /^V:/{print p "=" substr($0,3)}' /tmp/base-installed \
            | grep -vE '^(busybox|npm-[0-9]+|node-gyp)=' | tr '\n' ' ')"; \
    echo "runtime packages: ${pkgs}"; \
    mkdir -p /rootfs; \
    # shellcheck disable=SC2086
    apk add --root /rootfs --initdb --arch "${arch}" --no-cache --no-scripts \
      --keys-dir /etc/apk/keys --repositories-file /etc/apk/repositories ${pkgs}; \
    rm -rf /rootfs/var/cache/apk /rootfs/etc/apk/cache; \
    # No file capabilities may exist (they would fail to execute under no_new_privs).
    apk add --no-cache libcap-utils; \
    test -z "$(getcap -r /rootfs 2>/dev/null)"; \
    grep -q ':65532:' /rootfs/etc/passwd || echo 'nonroot:x:65532:65532:nonroot:/tmp:/sbin/nologin' >> /rootfs/etc/passwd; \
    grep -q ':65532:' /rootfs/etc/group || echo 'nonroot:x:65532:' >> /rootfs/etc/group; \
    test -x /rootfs/usr/bin/node; test -x /rootfs/usr/bin/dumb-init; \
    if [ -e /rootfs/bin/sh ] || [ -e /rootfs/usr/bin/sh ] || [ -e /rootfs/usr/bin/npm ] || [ -e /rootfs/sbin/apk ]; then \
      echo "minimal image must not contain a shell or package manager"; exit 1; \
    fi

# ----------------------------------------------------------- production
FROM scratch AS production
ARG VERSION=dev
ARG COMMIT=unknown
COPY --from=rootfs /rootfs/ /

WORKDIR /opt/mongo-express
COPY --from=build /dockerbuild/build /opt/mongo-express/build/
COPY --from=build /dockerbuild/public /opt/mongo-express/public/
COPY --from=build /dockerbuild/lib /opt/mongo-express/lib/
COPY --from=build /dockerbuild/app.js /opt/mongo-express/
COPY --from=build /dockerbuild/config.default.js /opt/mongo-express/
COPY --from=build /dockerbuild/build-assets.json /opt/mongo-express/
COPY --from=build /dockerbuild/package.json /opt/mongo-express/
COPY --from=build /dockerbuild/node_modules /opt/mongo-express/node_modules/

# "localhost" doesn't mean much in a container, so we adjust our default to the common service name "mongo" instead
# (and make sure the server listens outside the container, since "localhost" inside the container is usually difficult to access)
ENV ME_CONFIG_MONGODB_URL="mongodb://mongo:27017" \
    ME_CONFIG_MONGODB_ENABLE_ADMIN="true" \
    NODE_ENV="production" \
    VCAP_APP_HOST="0.0.0.0" \
    HOME="/tmp" \
    TMPDIR="/tmp" \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"

LABEL org.opencontainers.image.title="mongo-express" \
      org.opencontainers.image.description="mongo-express web admin for MongoDB (minimal Chainguard/Wolfi image)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.source="https://github.com/krishnamanaiducloud/mongo-express" \
      org.opencontainers.image.licenses="MIT"

EXPOSE 8081

# Any UID works (OpenShift assigns one); GID 0 gives group read access.
USER 65532:0

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD ["/usr/bin/node", "-e", "require('http').get('http://127.0.0.1:'+(process.env.PORT||8081)+(process.env.ME_CONFIG_HEALTH_CHECK_PATH||'/status'),r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]

# dumb-init (from the Chainguard node package set) forwards signals so Node
# shuts down on SIGTERM instead of being killed after the grace period.
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/usr/bin/node"]
CMD ["app.js"]
