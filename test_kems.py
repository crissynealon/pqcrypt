from secrets import compare_digest
from binascii import hexlify
import pytest

KEMS = {
    "firesaber" : "from pqcrypt.kem.firesaber import generate_keypair, encrypt, decrypt",
    "frodokem1344aes" : "from pqcrypt.kem.frodokem1344aes import generate_keypair, encrypt, decrypt",
    "frodokem1344shake" : "from pqcrypt.kem.frodokem1344shake import generate_keypair, encrypt, decrypt",
    "frodokem640aes" : "from pqcrypt.kem.frodokem640aes import generate_keypair, encrypt, decrypt",
    "frodokem640shake" : "from pqcrypt.kem.frodokem640shake import generate_keypair, encrypt, decrypt",
    "frodokem976aes" : "from pqcrypt.kem.frodokem976aes import generate_keypair, encrypt, decrypt",
    "frodokem976shake" : "from pqcrypt.kem.frodokem976shake import generate_keypair, encrypt, decrypt",
    "kyber1024" : "from pqcrypt.kem.kyber1024 import generate_keypair, encrypt, decrypt",
    "kyber1024_90s" : "from pqcrypt.kem.kyber1024_90s import generate_keypair, encrypt, decrypt",
    "kyber512" : "from pqcrypt.kem.kyber512 import generate_keypair, encrypt, decrypt",
    "kyber512_90s" : "from pqcrypt.kem.kyber512_90s import generate_keypair, encrypt, decrypt",
    "kyber768" : "from pqcrypt.kem.kyber768 import generate_keypair, encrypt, decrypt",
    "kyber768_90s" : "from pqcrypt.kem.kyber768_90s import generate_keypair, encrypt, decrypt",
    "lightsaber" : "from pqcrypt.kem.lightsaber import generate_keypair, encrypt, decrypt",
    "mceliece348864" : "from pqcrypt.kem.mceliece348864 import generate_keypair, encrypt, decrypt",
    "mceliece348864f" : "from pqcrypt.kem.mceliece348864f import generate_keypair, encrypt, decrypt",
    "mceliece460896" : "from pqcrypt.kem.mceliece460896 import generate_keypair, encrypt, decrypt",
    "mceliece460896f" : "from pqcrypt.kem.mceliece460896f import generate_keypair, encrypt, decrypt",
    "mceliece6688128" : "from pqcrypt.kem.mceliece6688128 import generate_keypair, encrypt, decrypt",
    "mceliece6688128f" : "from pqcrypt.kem.mceliece6688128f import generate_keypair, encrypt, decrypt",
    "mceliece6960119" : "from pqcrypt.kem.mceliece6960119 import generate_keypair, encrypt, decrypt",
    "mceliece6960119f" : "from pqcrypt.kem.mceliece6960119f import generate_keypair, encrypt, decrypt",
    "mceliece8192128" : "from pqcrypt.kem.mceliece8192128 import generate_keypair, encrypt, decrypt",
    "mceliece8192128f" : "from pqcrypt.kem.mceliece8192128f import generate_keypair, encrypt, decrypt",
    "ntruhps2048509" : "from pqcrypt.kem.ntruhps2048509 import generate_keypair, encrypt, decrypt",
    "ntruhps2048677" : "from pqcrypt.kem.ntruhps2048677 import generate_keypair, encrypt, decrypt",
    "ntruhps4096821" : "from pqcrypt.kem.ntruhps4096821 import generate_keypair, encrypt, decrypt",
    "ntruhrss701" : "from pqcrypt.kem.ntruhrss701 import generate_keypair, encrypt, decrypt",
    "saber" : "from pqcrypt.kem.saber import generate_keypair, encrypt, decrypt",
    "hqc128": "from pqcrypt.kem.hqc128 import generate_keypair, encrypt, decrypt",
    "hqc192": "from pqcrypt.kem.hqc192 import generate_keypair, encrypt, decrypt",
    "hqc256": "from pqcrypt.kem.hqc256 import generate_keypair, encrypt, decrypt",
    "mlkem512": "from pqcrypt.kem.mlkem512 import generate_keypair, encrypt, decrypt",
    "mlkem768": "from pqcrypt.kem.mlkem768 import generate_keypair, encrypt, decrypt",
    "mlkem1024": "from pqcrypt.kem.mlkem1024 import generate_keypair, encrypt, decrypt",
    # "dhkem": "from pqcrypt.kem.dhkem import generate_keypair, encrypt, decrypt",
    "xwing": "from pqcrypt.kem.xwing import generate_keypair, encrypt, decrypt",
    "sntryp761": "from pqcrypt.kem.sntryp761 import generate_keypair, encrypt, decrypt",
}

@pytest.mark.parametrize("kem", KEMS.keys())
def test_kem_algorithm(kem):
    try:
        exec(KEMS[kem], globals())
    except KeyError:
        raise SystemError(f"Unknown kem {kem}")

    # Alice generates a (public, secret) key pair
    public_key, secret_key = generate_keypair()
    print(f"{kem}: public_key", hexlify(public_key))
    print(f"{kem}: secret_key", hexlify(secret_key))

    # Bob derives a secret (the plaintext) and encrypts it with Alice's public key to produce a ciphertext
    ciphertext, plaintext_original = encrypt(public_key)
    print(f"{kem}: ciphertext", hexlify(ciphertext))
    print(f"{kem}: plaintext_original", hexlify(plaintext_original))

    # Alice decrypts Bob's ciphertext to derive the now shared secret
    plaintext_recovered = decrypt(secret_key, ciphertext)
    print(f"{kem}: plaintext_recovered", hexlify(plaintext_recovered))

    # Compare the original and recovered secrets in constant time
    assert compare_digest(plaintext_original, plaintext_recovered), f"{kem}: Secrets do not match!"


@pytest.mark.parametrize("kem", KEMS.keys())
def test_all(kem):
    test_kem_algorithm(kem)
