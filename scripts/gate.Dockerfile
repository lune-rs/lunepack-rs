# Image for the gate's Docker Linux stage (scripts/gate.sh, M1-D8): the pinned Rust image plus
# git, which the xtask tests drive and the slim image lacks. Built once; gate.sh tags it with
# this file's hash, so editing this file (including the digest) triggers one rebuild.
# Base: rust:1.99.1-slim-trixie, resolved 2026-11-12 with `docker pull` + `docker inspect`
# (RepoDigests). The tag alone is not trusted; the digest is.
FROM rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7
LABEL org.lunepack-rs.purpose="gate"
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
