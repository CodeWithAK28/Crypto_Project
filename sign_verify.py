from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)
with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

pss = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)

message = input("Enter the message to sign: ").encode("utf-8")

signature = private_key.sign(message, pss, hashes.SHA256())

with open("message.txt", "wb") as f:
    f.write(message)
with open("signature.bin", "wb") as f:
    f.write(signature)

print("\nMessage signed successfully")
print("Signature length:", len(signature), "bytes")
print("Signature (hex):", signature.hex())
print("Saved message.txt and signature.bin")

with open("message.txt", "rb") as f:
    received_message = f.read()
with open("signature.bin", "rb") as f:
    received_signature = f.read()

try:
    public_key.verify(received_signature, received_message, pss, hashes.SHA256())
    print("\nVerification: VALID - the message is authentic and unchanged")
except InvalidSignature:
    print("\nVerification: INVALID - the message or signature was tampered with")