from .._kem.mceliece348864 import ffi as __ffi, lib as __lib
from .common import _kem_keygen_factory, _kem_encaps_factory, _kem_decaps_factory, _kem_encrypt_factory, _kem_decrypt_factory

PUBLIC_KEY_SIZE = __lib.CFFI_CRYPTO_PUBLICKEYBYTES
SECRET_KEY_SIZE = __lib.CFFI_CRYPTO_SECRETKEYBYTES
CIPHERTEXT_SIZE = __lib.CFFI_CRYPTO_CIPHERTEXTBYTES
PLAINTEXT_SIZE = __lib.CFFI_CRYPTO_PLAINTEXTBYTES
SHAREDKEY_SIZE = __lib.CFFI_CRYPTO_BYTES

keygen = _kem_keygen_factory(__ffi, __lib)
encaps = _kem_encaps_factory(__ffi, __lib)
decaps = _kem_decaps_factory(__ffi, __lib)
encrypt = _kem_encrypt_factory(__ffi, __lib)
decrypt = _kem_decrypt_factory(__ffi, __lib)
