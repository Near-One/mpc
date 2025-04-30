from collections import deque
import os
import requests
from subprocess import run
import sys
import time
import traceback

IMAGE_DIGEST_FILE="/mnt/shared/image-hash"
DEFAULT_MANIFEST_HASH='sha256:d56f37c7f9597c1fcc17a9db40d1eb663018d4f0df3de6668b7dcd3a90eab904'
DEFAULT_IMAGE_HASH='sha256:84831fe2c8e9acd06086f466e1d4c14e7d976362e4cb3457c6e1da26a2365c6c'
DEFAULT_IMAGE_NAME='thomasknauthnear/mpc-node'
DEFAULT_TAGS='latest'

# thomasknauthnear/mpc-node@sha256:d56f37c7f9597c1fcc17a9db40d1eb663018d4f0df3de6668b7dcd3a90eab904
# thomasknauthnear/mpc-node@sha256:eea23e28b0045a58de933f70ee813b240397bcb9211395b37a2b197554365bf3

# docker image pull <repo/name:tag>@sha256:<repo digest>
#
# <repo digest> != <image id>
# <repo digest> ... docker image inspect alpine --format 'Digest: {{index .RepoDigests 0}}'
# <image id>    ... docker image inspect alpine --format 'ID: {{.Id}}'

# We use `docker pull nearone/mpc-node:latest` to fetch a new image after an update.
# We write the <image id> into $IMAGE_HASH_FILE
# 

# We want to globally enable DOCKER_CONTENT_TRUST=1 to ensure integrity of Docker images.

# Image integrity is only checked on `docker pull`. Afterwards, modifications are not detected.

def main():

    tags = os.environ.get("LAUNCHER_IMAGE_TAGS", DEFAULT_TAGS).split(',')

    if not os.path.isfile(IMAGE_DIGEST_FILE):
        with open(IMAGE_DIGEST_FILE, 'w') as f:
            f.write(DEFAULT_IMAGE_HASH)

    # security: here we trust image registry and pre-image resistance
    # go fetch hardcoded image has, `docker image pull image_name_and_hash`?
    image_digest = open(IMAGE_DIGEST_FILE).readline().strip()

    REGISTRY = 'registry.hub.docker.com'
    manifest_digest = get_manifest_digest(REGISTRY, DEFAULT_IMAGE_NAME, tags, image_digest)

    name_and_digest = DEFAULT_IMAGE_NAME + "@" + manifest_digest

    env = os.environ.copy()
    # TODO Check if we need DOCKER_CONTENT_TRUST=1 to have docker verify the integrity of an image.
    env['DOCKER_CONTENT_TRUST'] = '1'
    proc = run(["docker", "pull", name_and_digest], env=env)

    if proc.returncode:
        raise RuntimeError("docker pull returned non-zero exit code %d" % proc.returncode)

    proc = run(["docker", "image", "inspect", "--format", "{{index .ID}}", name_and_digest], capture_output=True)

    if proc.returncode:
        raise RuntimeError("docker image inspect returned non-zero exit code: %d" % proc.returncode)

    pulled_image_digest = proc.stdout.decode('utf-8').strip()

    if pulled_image_digest != image_digest:
        raise RuntimeError("Wrong image digest %s. Expected digest is %s" % (pulled_image_digest, image_digest))

    # TODO extend rtmr3 with image_digest; API https://github.com/Dstack-TEE/dstack/pull/160

    # use docker compose/run to start image
    # exec('docker run %s' % image_name_and_hash)
    proc = run(['docker', 'run', image_digest])

    if proc.returncode:
        raise RuntimeError("docker run non-zero exit code %d", proc.returncode)

# API doc https://distribution.github.io/distribution/spec/api/
def get_manifest_digest(registry_url: str, image_name: str, tags: list[str], image_digest: str):
    '''Given an `image_digest` returns a manifest digest.
    
       Manifest digest can be used with `docker pull` whereas image digest cannot.
    '''
    if not tags:
        raise Exception(f"No tags found for image {image_name}")

    # We need a token to fetch manifests
    token_resp = requests.get(f'https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image_name}:pull')
    token_resp.raise_for_status()
    token = token_resp.json().get('token', [])

    tags = deque(tags)

    while tags:
        tag = tags.popleft()

        manifest_url = f"https://{registry_url}/v2/{image_name}/manifests/{tag}"
        headers = {"Accept": "application/vnd.docker.distribution.manifest.v2+json",
                   "Authorization": f"Bearer {token}"}
        manifest_resp = requests.get(manifest_url, headers=headers)
        if manifest_resp.status_code != 200:
            print(f"Warning: Could not fetch manifest for tag {tag}: {manifest_resp.text} {manifest_resp.headers}")
            continue
        
        manifest = manifest_resp.json()

        match manifest['mediaType']:
            case 'application/vnd.oci.image.index.v1+json':
                for image_manifest in manifest['manifests']:
                    platform = image_manifest['platform']
                    if platform['architecture'] == 'amd64' and platform['os'] == 'linux':
                        tags.append(image_manifest['digest'])
                continue
            case 'application/vnd.docker.distribution.manifest.v2+json' | \
                 'application/vnd.oci.image.manifest.v1+json':
                config_digest = manifest['config']['digest']

        if config_digest == image_digest:
            return manifest_resp.headers.get('Docker-Content-Digest')

        # Avoid getting rate-limited by the server.
        time.sleep(0.1)

    raise Exception("Image hash not found among tags.")

if __name__ == "__main__":
    try:
        main()
        sys.exit(0)
    except Exception as e:
        print("Error:", str(e), file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
