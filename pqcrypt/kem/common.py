from ..common import _run_in_threadpool

def _kem_keygen_factory(ffi, lib, use_threadpool=False):
    def keygen():
        public_key_buf = ffi.new("uint8_t [{}]".format(lib.CRYPTO_PUBLICKEYBYTES))
        secret_key_buf = ffi.new("uint8_t [{}]".format(lib.CRYPTO_SECRETKEYBYTES))

        if 0 != lib.crypto_kem_keypair(public_key_buf, secret_key_buf):
            raise RuntimeError("KEM keypair generation failed")

        public_key = bytes(ffi.buffer(public_key_buf, lib.CRYPTO_PUBLICKEYBYTES))
        secret_key = bytes(ffi.buffer(secret_key_buf, lib.CRYPTO_SECRETKEYBYTES))

        return public_key, secret_key

    return _run_in_threadpool(keygen) if use_threadpool else keygen


def _kem_encaps_factory(ffi, lib, use_threadpool=False):
    def encaps(public_key):
        if not isinstance(public_key, bytes):
            raise TypeError("'public_key' must be of type 'bytes'")

        if len(public_key) != lib.CRYPTO_PUBLICKEYBYTES:
            raise ValueError(f"'public_key' must be of length '{ lib.CRYPTO_PUBLICKEYBYTES }'")

        ciphertext_buf = ffi.new("uint8_t [{}]".format(lib.CRYPTO_CIPHERTEXTBYTES))
        plaintext_buf = ffi.new("uint8_t [{}]".format(lib.CRYPTO_BYTES))

        if 0 != lib.crypto_kem_enc(ciphertext_buf, plaintext_buf, public_key):
            raise RuntimeError("KEM encryption failed")

        ciphertext = bytes(ffi.buffer(ciphertext_buf, lib.CRYPTO_CIPHERTEXTBYTES))
        plaintext = bytes(ffi.buffer(plaintext_buf, lib.CRYPTO_BYTES))

        return ciphertext, plaintext

    return _run_in_threadpool(encaps) if use_threadpool else encaps


def _kem_decaps_factory(ffi, lib, use_threadpool=False):
    def decaps(secret_key, ciphertext):
        if not isinstance(secret_key, bytes):
            raise TypeError("'secret_key' must be of type 'bytes'")

        if not isinstance(ciphertext, bytes):
            raise TypeError("'ciphertext' must be of type 'bytes'")

        if len(secret_key) != lib.CRYPTO_SECRETKEYBYTES:
            raise ValueError(f"'secret_key' must be of length '{ lib.CRYPTO_SECRETKEYBYTES }'")

        if len(ciphertext) != lib.CRYPTO_CIPHERTEXTBYTES:
            raise ValueError(f"'ciphertext' must be of length '{ lib.CRYPTO_CIPHERTEXTBYTES }'")

        plaintext_buf = ffi.new("uint8_t [{}]".format(lib.CRYPTO_BYTES))

        if 0 != lib.crypto_kem_dec(plaintext_buf, ciphertext, secret_key):
            raise RuntimeError("KEM decryption failed")

        return bytes(ffi.buffer(plaintext_buf, lib.CRYPTO_BYTES))

    return _run_in_threadpool(decaps) if use_threadpool else decaps

def _kem_encrypt_factory(ffi, lib, use_threadpool=False):
    def encrypt(public_key):
        if not isinstance(public_key, bytes):
            raise TypeError("'public_key' must be of type 'bytes'")

        if len(public_key) != lib.CRYPTO_PUBLICKEYBYTES:
            raise ValueError(f"'public_key' must be of length '{ lib.CRYPTO_PUBLICKEYBYTES }'")

        ciphertext_buf = ffi.new("uint8_t [{}]".format(lib.CRYPTO_CIPHERTEXTBYTES))
        plaintext_buf = ffi.new("uint8_t [{}]".format(lib.CRYPTO_BYTES))

        if 0 != lib.crypto_kem_enc(ciphertext_buf, plaintext_buf, public_key):
            raise RuntimeError("KEM encryption failed")

        ciphertext = bytes(ffi.buffer(ciphertext_buf, lib.CRYPTO_CIPHERTEXTBYTES))
        plaintext = bytes(ffi.buffer(plaintext_buf, lib.CRYPTO_BYTES))

        return ciphertext, plaintext

    return _run_in_threadpool(encrypt) if use_threadpool else encrypt

def _kem_decrypt_factory(ffi, lib, use_threadpool=False):
    def encrypt(public_key):
        if not isinstance(public_key, bytes):
            raise TypeError("'public_key' must be of type 'bytes'")

        if len(public_key) != lib.CRYPTO_PUBLICKEYBYTES:
            raise ValueError(f"'public_key' must be of length '{ lib.CRYPTO_PUBLICKEYBYTES }'")

        ciphertext_buf = ffi.new("uint8_t [{}]".format(lib.CRYPTO_CIPHERTEXTBYTES))
        plaintext_buf = ffi.new("uint8_t [{}]".format(lib.CRYPTO_BYTES))

        if 0 != lib.crypto_kem_enc(ciphertext_buf, plaintext_buf, public_key):
            raise RuntimeError("KEM encryption failed")

        ciphertext = bytes(ffi.buffer(ciphertext_buf, lib.CRYPTO_CIPHERTEXTBYTES))
        plaintext = bytes(ffi.buffer(plaintext_buf, lib.CRYPTO_BYTES))

        return ciphertext, plaintext

    return _run_in_threadpool(encrypt) if use_threadpool else encrypt

