import unittest

from launcher import get_manifest_digest

class TestLauncher(unittest.TestCase):
    def test_get_manifest_digest(self):
        registry_url = 'registry.hub.docker.com'
        image_name = 'thomasknauthnear/mpc-node'
        image_hash = 'sha256:84831fe2c8e9acd06086f466e1d4c14e7d976362e4cb3457c6e1da26a2365c6c'

        # result = get_manifest_digest(registry_url, image_name, image_hash)
        # print(f"Tag: {result['tag']}")
        # print(f"Manifest Digest: {result['manifest_digest']}")
        # self.assertEqual(result, 'sha256:d56f37c7f9597c1fcc17a9db40d1eb663018d4f0df3de6668b7dcd3a90eab904')

        # Use some random recent (at the time of writing) tag/image digest/manifest digest combination for testing
        image_name = 'nearone/mpc-node-gcp'
        image_hash = 'sha256:7e5a6bcb6707d134fc479cc293830c05ce45891f0977d467362cbb7f55cde46b'
        tags = ['8805536ab98d924d980a58ecc0518a8c90204bec']
        result = get_manifest_digest(registry_url, image_name, tags, image_hash)
        self.assertEqual(result, 'sha256:005943bccdd401e71c5408d65cf301eeb8bfc3926fe346023912412aafda2490')

if __name__ == '__main__':
    unittest.main()
