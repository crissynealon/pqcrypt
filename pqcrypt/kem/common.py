from ..common import _run_in_threadpool

# CFFI_CRYPTO_PUBLICKEYBYTES    public_key length
# CFFI_CRYPTO_SECRETKEYBYTES    secret_key length
# CFFI_CRYPTO_BYTES            shared_key length

# CFFI_CRYPTO_PLAINTEXTBYTES    one plain message length
# CFFI_CRYPTO_CIPHERTEXTBYTES   cipher text length


def _kem_keygen_factory(ffi, lib, use_threadpool=False):
    def keygen():
        public_key_buf = ffi.new("uint8_t [{}]".format(lib.CFFI_CRYPTO_PUBLICKEYBYTES))
        secret_key_buf = ffi.new("uint8_t [{}]".format(lib.CFFI_CRYPTO_SECRETKEYBYTES))

        if 0 != lib.cffi_crypto_keygen(public_key_buf, secret_key_buf):
            raise RuntimeError("KEM keygen generation failed")

        public_key = bytes(ffi.buffer(public_key_buf, lib.CFFI_CRYPTO_PUBLICKEYBYTES))
        secret_key = bytes(ffi.buffer(secret_key_buf, lib.CFFI_CRYPTO_SECRETKEYBYTES))

        return public_key, secret_key

    return _run_in_threadpool(keygen) if use_threadpool else keygen


def _kem_encaps_factory(ffi, lib, use_threadpool=False):
    def encaps(public_key):
        if not isinstance(public_key, bytes):
            raise TypeError("'public_key' must be of type 'bytes'")

        if len(public_key) != lib.CFFI_CRYPTO_PUBLICKEYBYTES:
            raise ValueError(f"'public_key' must be of length '{ lib.CFFI_CRYPTO_PUBLICKEYBYTES }'")

        ciphertext_buf = ffi.new("uint8_t [{}]".format(lib.CFFI_CRYPTO_CIPHERTEXTBYTES))
        sharedkey_buf = ffi.new("uint8_t [{}]".format(lib.CFFI_CRYPTO_BYTES))

        if 0 != lib.cffi_crypto_kem_encaps(ciphertext_buf, sharedkey_buf, public_key):
            raise RuntimeError("KEM encaps failed")

        ciphertext = bytes(ffi.buffer(ciphertext_buf, lib.CFFI_CRYPTO_CIPHERTEXTBYTES))
        sharedkey = bytes(ffi.buffer(sharedkey_buf, lib.CFFI_CRYPTO_BYTES))

        return ciphertext, sharedkey

    return _run_in_threadpool(encaps) if use_threadpool else encaps


def _kem_decaps_factory(ffi, lib, use_threadpool=False):
    def decaps(secret_key, ciphertext):
        if not isinstance(secret_key, bytes):
            raise TypeError("'secret_key' must be of type 'bytes'")

        if not isinstance(ciphertext, bytes):
            raise TypeError("'ciphertext' must be of type 'bytes'")

        if len(secret_key) != lib.CFFI_CRYPTO_SECRETKEYBYTES:
            raise ValueError(f"'secret_key' must be of length '{ lib.CFFI_CRYPTO_SECRETKEYBYTES }'")

        if len(ciphertext) != lib.CFFI_CRYPTO_CIPHERTEXTBYTES:
            raise ValueError(f"'ciphertext' must be of length '{ lib.CFFI_CRYPTO_CIPHERTEXTBYTES }'")

        sharedkey_buf = ffi.new("uint8_t [{}]".format(lib.CFFI_CRYPTO_BYTES))

        if 0 != lib.cffi_crypto_kem_decaps(sharedkey_buf, ciphertext, secret_key):
            raise RuntimeError("KEM decaps failed")

        return bytes(ffi.buffer(sharedkey_buf, lib.CFFI_CRYPTO_BYTES))

    return _run_in_threadpool(decaps) if use_threadpool else decaps

def _kem_encrypt_factory(ffi, lib, use_threadpool=False):
    # FIXME: add random bool for controling some other exceptions
    def encrypt(plaintext, public_key, random=False):
        ciphertext_buf = ffi.new("uint8_t [{}]".format(lib.CFFI_CRYPTO_CIPHERTEXTBYTES))

        if not isinstance(public_key, bytes):
            raise TypeError("'public_key' must be of type 'bytes'")

        if len(public_key) != lib.CFFI_CRYPTO_PUBLICKEYBYTES:
                raise ValueError(f"'public_key' must be of length '{ lib.CFFI_CRYPTO_PUBLICKEYBYTES }'")

        if not isinstance(plaintext, bytes):
            raise TypeError("'plaintext' must be of type 'bytes'")

        if random:
            plaintext_buf = ffi.new("uint8_t [{}]".format(lib.CFFI_CRYPTO_PLAINTEXTBYTES))
            if 0 != lib.cffi_crypto_encrypt(ciphertext_buf, plaintext_buf, public_key):
                raise RuntimeError("KEM encrypt failed")
        else:
            if len(plaintext) != lib.CFFI_CRYPTO_PLAINTEXTBYTES:
                raise ValueError(f"'plaintext' now only support be length '{ lib.CFFI_CRYPTO_PLAINTEXTBYTES }'")
            if 0 != lib.cffi_crypto_encrypt(ciphertext_buf, plaintext, public_key):
                raise RuntimeError("KEM encrypt failed")

        ciphertext = bytes(ffi.buffer(ciphertext_buf, lib.CFFI_CRYPTO_CIPHERTEXTBYTES))
        if random:
            plaintext = bytes(ffi.buffer(plaintext_buf, lib.CFFI_CRYPTO_PLAINTEXTBYTES))
            return ciphertext, plaintext
        else:
            return ciphertext

    return _run_in_threadpool(encrypt) if use_threadpool else encrypt


def _kem_decrypt_factory(ffi, lib, use_threadpool=False):
    def decrypt(ciphertext, secret_key):
        if not isinstance(secret_key, bytes):
            raise TypeError("'secret_key' must be of type 'bytes'")

        if len(secret_key) != lib.CFFI_CRYPTO_SECRETKEYBYTES:
            raise ValueError(f"'secret_key' must be of length '{ lib.CFFI_CRYPTO_PUBLICKEYBYTES }'")

        plaintext_buf = ffi.new("uint8_t [{}]".format(lib.CFFI_CRYPTO_PLAINTEXTBYTES))

        if len(ciphertext) != lib.CFFI_CRYPTO_CIPHERTEXTBYTES:
            raise ValueError(f"'ciphertext' must be of length '{ lib.CFFI_CRYPTO_CIPHERTEXTBYTES }'")

        if 0 != lib.cffi_crypto_decrypt(plaintext_buf, ciphertext, secret_key):
            raise RuntimeError("KEM decrypt failed")

        plaintext = bytes(ffi.buffer(plaintext_buf, lib.CFFI_CRYPTO_PLAINTEXTBYTES))

        return plaintext

    return _run_in_threadpool(decrypt) if use_threadpool else decrypt
