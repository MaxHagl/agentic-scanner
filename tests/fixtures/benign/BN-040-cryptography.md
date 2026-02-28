# cryptography

The `cryptography` package is a Python library that provides cryptographic recipes and
primitives. It is designed to be your "cryptographic standard library." It supports both
high-level recipes for common use cases and low-level cryptographic primitives.

## Installation

```bash
pip install cryptography
```

## Symmetric Encryption (Fernet)

Fernet is a symmetric encryption method that guarantees that a message encrypted with it
cannot be manipulated or read without the key.

```python
from cryptography.fernet import Fernet

# Generate a key (store this securely!)
key = Fernet.generate_key()
print(key)
# b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='

f = Fernet(key)

# Encrypt
message = b"A secret message"
token = f.encrypt(message)
print(token)
# b'gAAAAABk...'  (base64url-encoded ciphertext)

# Decrypt
plaintext = f.decrypt(token)
print(plaintext)
# b'A secret message'
```

### Key Rotation

```python
from cryptography.fernet import MultiFernet

key1 = Fernet(Fernet.generate_key())
key2 = Fernet(Fernet.generate_key())

# MultiFernet encrypts with first key, can decrypt with any
f = MultiFernet([key1, key2])
token = f.encrypt(b"Secret data")
```

## Asymmetric Cryptography (RSA)

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Encrypt with public key
public_key = private_key.public_key()
ciphertext = public_key.encrypt(
    b"data to encrypt",
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypt with private key
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

## Digital Signatures

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Sign with private key
signature = private_key.sign(
    b"message to sign",
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Verify with public key
try:
    public_key.verify(
        signature,
        b"message to sign",
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature valid")
except Exception:
    print("Signature invalid")
```

## Key Serialization

Keys can be serialized to PEM format for storage or transport.

```python
from cryptography.hazmat.primitives import serialization

# Serialize private key
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase")
)

# Serialize public key
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Load from PEM
from cryptography.hazmat.primitives.serialization import load_pem_private_key
private_key = load_pem_private_key(pem_data, password=b"passphrase")
```

## Hashing

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

digest = hashes.Hash(hashes.SHA256())
digest.update(b"First chunk")
digest.update(b"Second chunk")
result = digest.finalize()
print(result.hex())
```

## X.509 Certificates

```python
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .sign(key, hashes.SHA256())
)
```

_fixture_meta:
  id: BN-040
  expected_verdict: SAFE
  notes: "Crypto library with Fernet base64 keys and key material in examples — must not trigger PI-005"
