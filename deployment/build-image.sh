#!/bin/bash

# Script to reproducibly build MPC binary and the docker image.

DOCKERFILE=deployment/Dockerfile-gcp
: "${IMAGE_NAME:=mpc-node-gcp}"

if [ ! -e "$DOCKERFILE" ]; then
   echo "Must be called from project root!"
   exit 1
fi

# Create our own builder (build env) to enable reproducibile images
if ! docker buildx inspect buildkit_20 &>/dev/null; then
    docker buildx create --use --driver-opt image=moby/buildkit:v0.20.2 --name buildkit_20
fi

docker buildx build --builder buildkit_20 --no-cache \
    --build-arg SOURCE_DATE_EPOCH="0" \
    --output type=docker,name=$IMAGE_NAME,rewrite-timestamp=true \
    -f "$DOCKERFILE" .
