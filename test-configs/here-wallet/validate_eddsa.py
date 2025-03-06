import json
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

# JSON string containing the signature and public key
data = '''{
    "Eddsa": {
        "signature": "c8da15dcf1dc194ebac3b87114e08e0fd9ba0831c09a4271abda9aba613dc5edbee22d0bfd471bdc565811b9c304ab3b6c18086d60fbb911eebc3e39d8dfab09",
        "public_key": "f5945e4572d61d722f478a2b343e77a3c6fdb30e79472159a29ad9e8c0006b7e"
    }
}'''

# Parse JSON data
parsed = json.loads(data)
eddsa = parsed["Eddsa"]
signature_hex = eddsa["signature"]
public_key_hex = eddsa["public_key"]

# Convert hex strings to bytes
signature = bytes.fromhex(signature_hex)
public_key = bytes.fromhex(public_key_hex)

# Create a VerifyKey object using the public key bytes
vk = VerifyKey(public_key)

# Provided message in hex
message_hex = "57f42da8350f6a7c6ad567d678355a3bbd17a681117e7a892db30656d5caee32"
# Convert the message from hex to bytes
message = bytes.fromhex(message_hex)

# Attempt to verify the signature
try:
    vk.verify(message, signature)
    print("Signature is valid!")
except BadSignatureError:
    print("Signature is invalid!")
