from collections import deque
import os
import requests
from subprocess import run
import sys
import time
import traceback

IMAGE_HASH_FILE="/mnt/shared/image-hash"
DEFAULT_MANIFEST_HASH='sha256:d56f37c7f9597c1fcc17a9db40d1eb663018d4f0df3de6668b7dcd3a90eab904'
DEFAULT_IMAGE_HASH='sha256:84831fe2c8e9acd06086f466e1d4c14e7d976362e4cb3457c6e1da26a2365c6c'
DEFAULT_IMAGE_NAME='thomasknauthnear/mpc-node'

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

# Get the manifest digest w/o pulling/downloading the image.
#
# docker manifest inspect -v thomasknauthnear/mpc-node | jq -r '.Descriptor.digest'
#
# We want to globally enable DOCKER_CONTENT_TRUST=1 to ensure integrity of Docker images.

# Image integrity is only checked on `docker pull`. Afterwards, modifications are not detected.

def main():

    if not os.path.isfile(IMAGE_HASH_FILE):
        with open(IMAGE_HASH_FILE, 'w') as f:
            f.write(DEFAULT_IMAGE_HASH)

    # security: here we trust image registry and pre-image resistance
    # go fetch hardcoded image has, `docker image pull image_name_and_hash`?
    image_hash = open(IMAGE_HASH_FILE).readline().strip()

    # DOCKER_CONTENT_TRUST=1 requires us to be explicit (use its sha256) about which image we pull, i.e., pulling :latest will result in an error
    proc = run("docker manifest inspect -v thomasknauthnear/mpc-node | jq -r '.Descriptor.digest'",
               shell=True, capture_output=True)

    if proc.returncode:
        raise RuntimeError("docker manifest returned non-zero exit code %d" % proc.returncode)

    manifest_hash_latest = proc.stdout.decode('utf-8').strip()
    name_and_hash_latest = DEFAULT_IMAGE_NAME + "@" + manifest_hash_latest

    env = os.environ.copy()
    # TODO Check if we need DOCKER_CONTENT_TRUST=1 to have docker verify the integrity of an image.
    env['DOCKER_CONTENT_TRUST'] = '1'
    proc = run(["docker", "pull", name_and_hash_latest], env=env)

    if proc.returncode:
        raise RuntimeError("docker pull returned non-zero exit code %d" % proc.returncode)

    proc = run(["docker", "image", "inspect", "--format", "{{index .ID}}", name_and_hash_latest], capture_output=True)

    if proc.returncode:
        raise RuntimeError("docker image inspect returned non-zero exit code: %d" % proc.returncode)

    latest_image_id = proc.stdout.decode('utf-8').strip()

    if latest_image_id != image_hash:
        raise RuntimeError("Wrong image hash %s. Expected hash is %s" % (latest_image_id, image_hash))

    # use docker compose/run to start image
    # exec('docker run %s' % image_name_and_hash)
    proc = run(['docker', 'run', image_hash])

    if proc.returncode:
        raise RuntimeError("docker run non-zero exit code %d", proc.returncode)

    # at this point we could even extend rtmr3 with the image_file to reflect which particular mpc node we launched in the tdx quote (and not just user data)

# API doc https://distribution.github.io/distribution/spec/api/
def get_manifest_digest(registry_url: str, image_name: str, tags: list[str], image_hash: str):

    if not tags:
        raise Exception(f"No tags found for image {image_name}")

    token_resp = requests.get(f'https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image_name}:pull')
    token_resp.raise_for_status()
    token = token_resp.json().get('token', [])

    tags = deque(tags)

    # Fetching manifests requires an access token. Get the token.

    # https://registry.hub.docker.com/v2/thomasknauthnear/mpc-node/manifests/sha256:d56f37c7f9597c1fcc17a9db40d1eb663018d4f0df3de6668b7dcd3a90eab904

    # User needs to provide a tags we will check. This avoids iterating over all tags.
    # Step 2: Loop through all tags, fetch manifest and compare hashes
    while tags:
        tag = tags.popleft()
        print('====', tag)
        manifest_url = f"https://{registry_url}/v2/{image_name}/manifests/{tag}"
        headers = {"Accept": "application/vnd.docker.distribution.manifest.v2+json",
                   "Authorization": f"Bearer {token}"}
        manifest_resp = requests.get(manifest_url, headers=headers)
        if manifest_resp.status_code != 200:
            print(f"Warning: Could not fetch manifest for tag {tag}: {manifest_resp.text} {manifest_resp.headers}")
            continue
        
        manifest = manifest_resp.json()

        if manifest['mediaType'] == 'application/vnd.oci.image.index.v1+json':
            for image_manifest in manifest['manifests']:
                platform = image_manifest['platform']
                if platform['architecture'] == 'amd64' and platform['os'] == 'linux':
                    tags.append(image_manifest['digest'])
            continue
        elif manifest['mediaType'] == 'application/vnd.docker.distribution.manifest.v2+json':
        # 'config' holds the actual image hash
            print('tag', tag)
            print('manifest', manifest)
            config_digest = manifest.get('config', {}).get('digest')
        elif manifest['mediaType'] == 'application/vnd.oci.image.manifest.v1+json':
            config_digest = manifest['config']['digest']

        if config_digest == image_hash:
            # Return the manifest digest (from response headers)
            manifest_digest = manifest_resp.headers.get('Docker-Content-Digest')
            return manifest_digest
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
