from collections import deque
import logging
import os
import requests
from subprocess import run
import sys
import time
import traceback

# The volume where this file resides is shared between launcher and app.
# To avoid concurrent modifications, the launcher mounts the volume read-only!
IMAGE_DIGEST_FILE="/mnt/shared/image-digest"

def parse_env_file(path):
    '''
    Parse .env-style files.

    Provide implementation here to avoid external dependency.
    '''
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env

def main():

    # We want to globally enable DOCKER_CONTENT_TRUST=1 to ensure integrity of Docker images.
    if os.environ.get('DOCKER_CONTENT_TRUST', '0') != '1':
        raise RuntimeError("Environment variable DOCKER_CONTENT_TRUST must be set to 1.")

    # In dstack, /tapp/user_config provides unmeasured data to the CVM.
    # We use this interface to make some aspects of the launcher configurable.
    # *** Only security-irrelevant parts *** may be made configurable in this way, e.g., the specific image tag(s) we look up.
    DSTACK_USER_CONFIG_FILE = '/tapp/user_config'
    user_vars = parse_env_file(DSTACK_USER_CONFIG_FILE) if os.path.isfile(DSTACK_USER_CONFIG_FILE) else {}

    tags = user_vars.get('LAUNCHER_IMAGE_TAGS', 'latest').split(',')
    image_name = user_vars.get('LAUNCHER_IMAGE_NAME', 'nearone/mpc-node')
    registry = user_vars.get('LAUNCHER_REGISTRY', 'registry.hub.docker.com')

    # DEFAULT_IMAGE_DIGEST originates from the app-compose.json and its value is contained in the app's measurement.
    image_digest = os.environ["DEFAULT_IMAGE_DIGEST"]

    if os.path.isfile(IMAGE_DIGEST_FILE):
        image_digest = open(IMAGE_DIGEST_FILE).readline().strip()

    logging.info(f'Using image digest {image_digest}.')
    logging.info(f"Using tags {tags} to find matching image.")

    manifest_digest = get_manifest_digest(registry, image_name, tags, image_digest)

    name_and_digest = image_name + "@" + manifest_digest

    proc = run(["docker", "pull", name_and_digest])

    if proc.returncode:
        raise RuntimeError("docker pull returned non-zero exit code %d" % proc.returncode)

    proc = run(["docker", "image", "inspect", "--format", "{{index .ID}}", name_and_digest], capture_output=True)

    if proc.returncode:
        raise RuntimeError("docker image inspect returned non-zero exit code: %d" % proc.returncode)

    pulled_image_digest = proc.stdout.decode('utf-8').strip()

    if pulled_image_digest != image_digest:
        raise RuntimeError("Wrong image digest %s. Expected digest is %s" % (pulled_image_digest, image_digest))

    # Generate a quote before extending RTMR3 with the image digest
    proc = run(['curl', '--unix-socket', '/var/run/dstack.sock', '-X', 'POST', 'http://dstack/GetQuote', '-H', 'Content-Type: application/json', '-d', '{"report_data": ""}'],
               capture_output=True)
    if proc.returncode:
        raise RuntimeError("getting quote failed with error code %d" % proc.returncode)
    logging.info("Quote: %s" % proc.stdout.decode('utf-8').strip())

    # Python's requests package cannot natively talk HTTP over a unix socket (which is the API exposed by dstack's guest agent).
    # To avoid installing another Python depdendency, namely requests-unixsocket, we just use curl.
    extend_rtmr3_json = '{"event": "launcher-image-digest","payload": "%s"}' % image_digest.split(':')[1]
    proc = run(['curl', '--unix-socket', '/var/run/dstack.sock', '-X', 'POST', 'http://dstack/EmitEvent', '-H', 'Content-Type: application/json', '-d', extend_rtmr3_json])

    if proc.returncode:
        raise RuntimeError("extending rtmr3 failed with error code %d" % proc.returncode)

    # Get quote after extending RTMR3 with the image digest
    proc = run(['curl', '--unix-socket', '/var/run/dstack.sock', '-X', 'POST', 'http://dstack/GetQuote', '-H', 'Content-Type: application/json', '-d', '{"report_data": ""}'],
               capture_output=True)
    if proc.returncode:
        raise RuntimeError("getting quote failed with error code %d" % proc.returncode)
    logging.info("Quote: %s" % proc.stdout.decode('utf-8').strip())

    # Start the app.
    proc = run(['docker', 'run', '--detach', image_digest])

    if proc.returncode:
        raise RuntimeError("docker run non-zero exit code %d", proc.returncode)

def get_manifest_digest(registry_url: str, image_name: str, tags: list[str], image_digest: str):
    '''Given an `image_digest` returns a manifest digest.
    
       `docker pull` requires a manifest digest. This function translates an image digest into a manifest digest.

       API doc for image registry https://distribution.github.io/distribution/spec/api/
    '''
    if not tags:
        raise Exception(f"No tags found for image {image_name}")

    # We need an authorization token to fetch manifests.
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
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s'
        )

        main()
        sys.exit(0)
    except Exception as e:
        print("Error:", str(e), file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
