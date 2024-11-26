from dataclasses import dataclass, field
from typing import List, Optional

HQC128_HEADER = '''
#define cffi_crypto_keygen PQCLEAN_HQC128_CLEAN_crypto_kem_keypair
#define cffi_crypto_kem_encaps PQCLEAN_HQC128_CLEAN_crypto_kem_enc
#define cffi_crypto_kem_decaps PQCLEAN_HQC128_CLEAN_crypto_kem_dec
#define cffi_crypto_encrypt PQCRYPT_HQC128_encrypt
#define cffi_crypto_decrypt PQCRYPT_HQC128_decrypt

#define CRYPTO_ALGNAME PQCLEAN_HQC128_CLEAN_CRYPTO_ALGNAME
#define CRYPTO_BYTES PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES
'''

HQC192_HEADER = '''
#define cffi_crypto_keygen PQCLEAN_HQC192_CLEAN_crypto_kem_keypair
#define cffi_crypto_kem_encaps PQCLEAN_HQC192_CLEAN_crypto_kem_enc
#define cffi_crypto_kem_decaps PQCLEAN_HQC192_CLEAN_crypto_kem_dec
#define cffi_crypto_encrypt PQCRYPT_HQC192_encrypt
#define cffi_crypto_decrypt PQCRYPT_HQC192_decrypt

#define CRYPTO_ALGNAME PQCLEAN_HQC192_CLEAN_CRYPTO_ALGNAME
#define CRYPTO_BYTES PQCLEAN_HQC192_CLEAN_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES
'''

HQC256_HEADER = '''
#define cffi_crypto_keygen PQCLEAN_HQC256_CLEAN_crypto_kem_keypair
#define cffi_crypto_kem_encaps PQCLEAN_HQC256_CLEAN_crypto_kem_enc
#define cffi_crypto_kem_decaps PQCLEAN_HQC256_CLEAN_crypto_kem_dec
#define cffi_crypto_encrypt PQCRYPT_HQC256_encrypt
#define cffi_crypto_decrypt PQCRYPT_HQC256_decrypt

#define CRYPTO_ALGNAME PQCLEAN_HQC256_CLEAN_CRYPTO_ALGNAME
#define CRYPTO_BYTES PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES
'''

MLKEM512_HEADER = '''
#define cffi_crypto_keygen PQCLEAN_MLKEM512_CLEAN_cffi_crypto_keygen
#define cffi_crypto_kem_encaps PQCLEAN_MLKEM512_CLEAN_cffi_crypto_kem_encaps
#define cffi_crypto_kem_decaps PQCLEAN_MLKEM512_CLEAN_cffi_crypto_kem_decaps

#define CRYPTO_BYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES
'''

MLKEM768_HEADER = '''
#define cffi_crypto_keygen PQCLEAN_MLKEM768_CLEAN_cffi_crypto_keygen
#define cffi_crypto_kem_encaps PQCLEAN_MLKEM768_CLEAN_cffi_crypto_kem_encaps
#define cffi_crypto_kem_decaps PQCLEAN_MLKEM768_CLEAN_cffi_crypto_kem_decaps

#define CRYPTO_BYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES
'''

MLKEM1024_HEADER = '''
#define cffi_crypto_keygen PQCLEAN_MLKEM1024_CLEAN_cffi_crypto_keygen
#define cffi_crypto_kem_encaps PQCLEAN_MLKEM1024_CLEAN_cffi_crypto_kem_encaps
#define cffi_crypto_kem_decaps PQCLEAN_MLKEM1024_CLEAN_cffi_crypto_kem_decaps

#define CRYPTO_BYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES
'''

SNTRUP761_HEADER='''
#define cffi_crypto_keygen PQCLEAN_SNTRUP761_CLEAN_cffi_crypto_keygen
#define cffi_crypto_kem_encaps PQCLEAN_SNTRUP761_CLEAN_cffi_crypto_kem_encaps
#define cffi_crypto_kem_decaps PQCLEAN_SNTRUP761_CLEAN_cffi_crypto_kem_decaps

#define CRYPTO_SECRETKEYBYTES PQCLEAN_SNTRUP761_CLEAN_CRYPTO_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_SNTRUP761_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_SNTRUP761_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_BYTES PQCLEAN_SNTRUP761_CLEAN_CRYPTO_BYTES
'''

XWING_HEADER = '''
#define cffi_crypto_keygen xwing_ref_keypair
#define cffi_crypto_kem_encaps xwing_ref_enc
#define cffi_crypto_kem_decaps xwing_ref_dec

#define CRYPTO_BYTES xwing_BYTES
#define CRYPTO_CIPHERTEXTBYTES xwing_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES xwing_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES xwing_SECRETKEYBYTES
'''

TM_HEADER = '''
#define cffi_crypto_keygen xwing_ref_keypair
#define cffi_crypto_kem_encaps xwing_ref_enc
#define cffi_crypto_kem_decaps xwing_ref_dec

#define CRYPTO_BYTES xwing_BYTES
#define CRYPTO_CIPHERTEXTBYTES xwing_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES xwing_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES xwing_SECRETKEYBYTES
'''

@dataclass
class AlgorithmConfig:
    """_summary_
    path (str)
    is_kem (bool)
    is_common (bool)
    extra_header (Optional[str])
    extra_sources (Optional[List[str]])
    extra_include_dirs (Optional[List[str]])
    extra_compiler_args (Optional[List[str]])
    extra_link_args (Optional[List[str]])
    extra_libraries (Optional[List[str]])
    """
    path: str
    is_kem: bool = True
    is_common: bool = True
    extra_header: Optional[str] = None
    extra_sources: List[str] = field(default_factory=list)
    extra_include_dirs: List[str] = field(default_factory=list)
    extra_compiler_args: List[str] = field(default_factory=list)
    extra_link_args: List[str] = field(default_factory=list)
    extra_libraries: List[str] = field(default_factory=list)

SUPPORT_ALGORITHMS = []

ALGORITHMS = {
    "firesaber": AlgorithmConfig(path = "firesaber"),
    "frodokem1344aes": AlgorithmConfig(path = "frodokem1344aes"),
    "frodokem1344shake": AlgorithmConfig(path = "frodokem1344shake"),
    "frodokem640aes": AlgorithmConfig(path = "frodokem640aes"),
    "frodokem640shake": AlgorithmConfig(path = "frodokem640shake"),
    "frodokem976aes": AlgorithmConfig(path = "frodokem976aes"),
    "frodokem976shake": AlgorithmConfig(path = "frodokem976shake"),
    "kyber1024": AlgorithmConfig(path = "kyber1024"),
    "kyber1024_90s": AlgorithmConfig(path = "kyber1024-90s"),
    "kyber512": AlgorithmConfig(path = "kyber512"),
    "kyber512_90s": AlgorithmConfig(path = "kyber512-90s"),
    "kyber768": AlgorithmConfig(path = "kyber768"),
    "kyber768_90s": AlgorithmConfig(path = "kyber768-90s"),
    "lightsaber": AlgorithmConfig(path = "lightsaber"),
    "mceliece348864": AlgorithmConfig(path = "mceliece348864"),
    "mceliece348864_clean": AlgorithmConfig(path = "mceliece348864-clean"),
    "mceliece348864f": AlgorithmConfig(path = "mceliece348864f"),
    "mceliece348864f_clean": AlgorithmConfig(path = "mceliece348864f-clean"),
    "mceliece460896": AlgorithmConfig(path = "mceliece460896"),
    "mceliece460896_clean": AlgorithmConfig(path = "mceliece460896-clean"),
    "mceliece460896f": AlgorithmConfig(path = "mceliece460896f"),
    "mceliece460896f_clean": AlgorithmConfig(path = "mceliece460896f-clean"),
    "mceliece6688128": AlgorithmConfig(path = "mceliece6688128"),
    "mceliece6688128_clean": AlgorithmConfig(path = "mceliece6688128-clean"),
    "mceliece6688128f": AlgorithmConfig(path = "mceliece6688128f"),
    "mceliece6688128f_clean": AlgorithmConfig(path = "mceliece6688128f-clean"),
    "mceliece6960119": AlgorithmConfig(path = "mceliece6960119"),
    "mceliece6960119_clean": AlgorithmConfig(path = "mceliece6960119-clean"),
    "mceliece6960119f": AlgorithmConfig(path = "mceliece6960119f"),
    "mceliece6960119f_clean": AlgorithmConfig(path = "mceliece6960119f-clean"),
    "mceliece8192128": AlgorithmConfig(path = "mceliece8192128"),
    "mceliece8192128_clean": AlgorithmConfig(path = "mceliece8192128-clean"),
    "mceliece8192128f": AlgorithmConfig(path = "mceliece8192128f"),
    "mceliece8192128f_clean": AlgorithmConfig(path = "mceliece8192128f-clean"),
    "ntruhps2048509": AlgorithmConfig(path = "ntruhps2048509"),
    "ntruhps2048677": AlgorithmConfig(path = "ntruhps2048677"),
    "ntruhps4096821": AlgorithmConfig(path = "ntruhps4096821"),
    "ntruhrss701": AlgorithmConfig(path = "ntruhrss701"),
    "saber": AlgorithmConfig(path = "saber"),
    "hqc128": AlgorithmConfig(path = "hqc128"),
    "hqc192": AlgorithmConfig(path = "hqc192"),
    "hqc256": AlgorithmConfig(path = "hqc256"),
    "mlkem512": AlgorithmConfig(path = "mlkem512"),
    "mlkem768": AlgorithmConfig(path = "mlkem768"),
    "mlkem1024": AlgorithmConfig(path = "mlkem1024"),
    "sntryp761": AlgorithmConfig(path="sntryp761"),

    # hybird KEM
    # "xwing": AlgorithmConfig(path = "xwing",
    #                         is_common=False,
    #                         extra_sources = ["mlkem/ref"],
    #                         extra_header = XWING_HEADER,
    #                         extra_include_dirs = ["mlkem"],
    #                         extra_libraries = ["25519"]
    #                        ),
    # "tm": AlgorithmConfig(path = "tm",
    #                         is_common=False,
    #                         extra_sources = ["mlkem/ref"],
    #                         extra_header = XWING_HEADER,
    #                         extra_include_dirs = ["mlkem"],
    #                         extra_libraries = ["25519"]
    #                        ),
}