from encodings.hex_codec import hex_decode

from binascii import unhexlify
from ecdsa import VerifyingKey, BadSignatureError, SECP256k1


signature_data = {
    "big_r": "03EACD8653641229EEBC13EA9AA09994E9273319D5D1061DE709B75A839D81F038",
    "signature": "577E61A221BA7762D52FEA57D3A463F71096AFE235544C259856A1926846D612"
}
# signature_data = {
#     "big_r": "02507511D55B4D10B59B92B01A4CDC19423D4B53BBD856B8DFB47BA8B5E0369D0D",
#     "signature": "62835F2A9F49A47152E0603E2BA91AC127D7378A6EBEFF476F25FC91B4DC1E4E"
# }
public_key_data = {
    "public_key": "0223DF41BEC7F924B62DA79D2FD80D8F99F79115085D9A95B8BD082E3F22F9A738"
    # "public_key": "23DF41BEC7F924B62DA79D2FD80D8F99F79115085D9A95B8BD082E3F22F9A738"
}

# message = b"57f42da8350f6a7c6ad567d678355a3bbd17a681117e7a892db30656d5caee32"
message = unhexlify('57f42da8350f6a7c6ad567d678355a3bbd17a681117e7a892db30656d5caee32')

###################

class Identity:
    def __init__(self, s):
        self._s = s

    def digest(self):
        return self._s

public_key_hex = public_key_data["public_key"]
public_key_bytes = unhexlify(public_key_hex)
verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1, hashfunc=Identity)

# Parse signature
big_r_bytes = unhexlify(signature_data["big_r"][2:])
signature_bytes = unhexlify(signature_data["signature"])

concatenated_signature = big_r_bytes + signature_bytes

# Create a VerifyingKey object

# Verify the signature
if verifying_key.verify(concatenated_signature, message):
    print("Signature is valid.")
else:
    print("Signature is invalid.")
