# Deploy and Upgrade an MPC Node on dstack

The launcher is a single Python script: [launcher.py](launcher.py)

## Reproducible builds

- [Makefile](Makefile): use this to build the mpc binary in a reproducible manner
- [deployment/Dockerfile-gcp](deployment/Dockerfile-gcp) Dockerfile with all dependencies pinned to specific versions, e.g., other Dockerfile via sha256 digests and Linux distribution packages via explicit version strings
- [deployment/build-image.sh](deployment/build-image.sh) drives the build process

For example, I ran `deployment/build-image.sh` on the git commit [ef3f1e7...](https://github.com/Near-One/mpc/commit/ef3f1e7f862d447de60e91d32dadf68696eb6a58). The resulting Docker image digest was

```
sha256:dcbd3b8c8ae35d2ba63b25d6b617ce8b7faabb0af96ffa2e35b08a50258ebfa4
```

and the MPC binary digest was

```
5dd1a80f842d08753184334466e97d55e5caa3dbcd93af27097d11e926d7f823
```

The respective commands to find either are

```
docker image inspect mpc-node-gcp:latest | jq '.[0].Id'
```

Note, the image digest used with `docker run` is the output of the `docker image inspect ...` command.

```
docker run --rm dcbd3b8c8ae35d2ba63b25d6b617ce8b7faabb0af96ffa2e35b08a50258ebfa4 cat /app/mpc-node | sha256sum
```

Opens: write a script utilizing `vmm-cli.py` from dstack to deploy an mpc node

- Artifacts to deploy a node
    - Scripts to a) reproducibly build the mpc binary and b) reproducibly build a docker image containing the mpc binary
- Actual upgrade procedure
    - Write new image hash to /mnt/shared/image-digest
    - Shut down cvm
    - Amend LAUNCHER_IMAGE_TAGS if necessary; can be done from host by editing ./meta-dstack/build/run/*/shared/.user-config
    - 
