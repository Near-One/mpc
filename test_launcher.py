import unittest

from launcher import get_manifest_digest

class TestLauncher(unittest.TestCase):
    def test_get_manifest_digest(self):

        # Use a recent (at the time of writing) tag/image digest/manifest digest combination for testing
        registry_url = 'registry.hub.docker.com'
        image_name = 'nearone/mpc-node-gcp'
        image_hash = 'sha256:7e5a6bcb6707d134fc479cc293830c05ce45891f0977d467362cbb7f55cde46b'
        expected_manifest_digest = 'sha256:005943bccdd401e71c5408d65cf301eeb8bfc3926fe346023912412aafda2490'
        tags = ['8805536ab98d924d980a58ecc0518a8c90204bec']
        result = get_manifest_digest(registry_url, image_name, tags, image_hash)
        self.assertEqual(result, expected_manifest_digest)

if __name__ == '__main__':
    unittest.main()
