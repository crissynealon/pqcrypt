from dataclasses import dataclass, field
from typing import List, Optional

HQC128_HEADER = '''
#define crypto_kem_keypair PQCLEAN_HQC128_CLEAN_crypto_kem_keypair
#define crypto_kem_enc PQCLEAN_HQC128_CLEAN_crypto_kem_enc
#define crypto_kem_dec PQCLEAN_HQC128_CLEAN_crypto_kem_dec

#define CRYPTO_BYTES PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES
'''

HQC192_HEADER = '''
#define crypto_kem_keypair PQCLEAN_HQC192_CLEAN_crypto_kem_keypair
#define crypto_kem_enc PQCLEAN_HQC192_CLEAN_crypto_kem_enc
#define crypto_kem_dec PQCLEAN_HQC192_CLEAN_crypto_kem_dec

#define CRYPTO_BYTES PQCLEAN_HQC192_CLEAN_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES
'''

HQC256_HEADER = '''
#define crypto_kem_keypair PQCLEAN_HQC256_CLEAN_crypto_kem_keypair
#define crypto_kem_enc PQCLEAN_HQC256_CLEAN_crypto_kem_enc
#define crypto_kem_dec PQCLEAN_HQC256_CLEAN_crypto_kem_dec

#define CRYPTO_BYTES PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES
'''

MLKEM512_HEADER = '''
#define crypto_kem_keypair PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair
#define crypto_kem_enc PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc
#define crypto_kem_dec PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec

#define CRYPTO_BYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES
'''

MLKEM768_HEADER = '''
#define crypto_kem_keypair PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair
#define crypto_kem_enc PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc
#define crypto_kem_dec PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec

#define CRYPTO_BYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES
'''

MLKEM1024_HEADER = '''
#define crypto_kem_keypair PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair
#define crypto_kem_enc PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc
#define crypto_kem_dec PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec

#define CRYPTO_BYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES
'''

XWING_HEADER = '''
#define crypto_kem_keypair xwing_ref_keypair
#define crypto_kem_enc xwing_ref_enc
#define crypto_kem_dec xwing_ref_dec

#define CRYPTO_BYTES xwing_BYTES
#define CRYPTO_CIPHERTEXTBYTES xwing_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES xwing_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES xwing_SECRETKEYBYTES
'''

@dataclass
class AlgorithmConfig:
    """_summary_
    attribues:
        path (str)
        is_kem (bool)
        extra_header (Optional[str])
        extra_sources (Optional[List[str]])
        extra_include_dirs (Optional[List[str]])
        extra_compiler_args (Optional[List[str]])
        extra_link_args (Optional[List[str]])
        extra_libraries (Optional[List[str]])
    """
    path: str
    is_kem: bool
    extra_header: Optional[str] = None
    extra_sources: List[str] = field(default_factory=list)
    extra_include_dirs: List[str] = field(default_factory=list)
    extra_compiler_args: List[str] = field(default_factory=list)
    extra_link_args: List[str] = field(default_factory=list)
    extra_libraries: List[str] = field(default_factory=list)

SUPPORT_ALGORITHMS = []

ALGORITHMS = {
    "firesaber": AlgorithmConfig(path = "firesaber", is_kem = True),
    "frodokem1344aes": AlgorithmConfig(path = "frodokem1344aes", is_kem = True),
    "frodokem1344shake": AlgorithmConfig(path = "frodokem1344shake", is_kem = True),
    "frodokem640aes": AlgorithmConfig(path = "frodokem640aes", is_kem = True),
    "frodokem640shake": AlgorithmConfig(path = "frodokem640shake", is_kem = True),
    "frodokem976aes": AlgorithmConfig(path = "frodokem976aes", is_kem = True),
    "frodokem976shake": AlgorithmConfig(path = "frodokem976shake", is_kem = True),
    "kyber1024": AlgorithmConfig(path = "kyber1024", is_kem = True),
    "kyber1024_90s": AlgorithmConfig(path = "kyber1024-90s", is_kem = True),
    "kyber512": AlgorithmConfig(path = "kyber512", is_kem = True),
    "kyber512_90s": AlgorithmConfig(path = "kyber512-90s", is_kem = True),
    "kyber768": AlgorithmConfig(path = "kyber768", is_kem = True),
    "kyber768_90s": AlgorithmConfig(path = "kyber768-90s", is_kem = True),
    "lightsaber": AlgorithmConfig(path = "lightsaber", is_kem = True),
    "mceliece348864": AlgorithmConfig(path = "mceliece348864", is_kem = True),
    "mceliece348864f": AlgorithmConfig(path = "mceliece348864f", is_kem = True),
    "mceliece460896": AlgorithmConfig(path = "mceliece460896", is_kem = True),
    "mceliece460896f": AlgorithmConfig(path = "mceliece460896f", is_kem = True),
    "mceliece6688128": AlgorithmConfig(path = "mceliece6688128", is_kem = True),
    "mceliece6688128f": AlgorithmConfig(path = "mceliece6688128f", is_kem = True),
    "mceliece6960119": AlgorithmConfig(path = "mceliece6960119", is_kem = True),
    "mceliece6960119f": AlgorithmConfig(path = "mceliece6960119f", is_kem = True),
    "mceliece8192128": AlgorithmConfig(path = "mceliece8192128", is_kem = True),
    "mceliece8192128f": AlgorithmConfig(path = "mceliece8192128f", is_kem = True),
    "ntruhps2048509": AlgorithmConfig(path = "ntruhps2048509", is_kem = True),
    "ntruhps2048677": AlgorithmConfig(path = "ntruhps2048677", is_kem = True),
    "ntruhps4096821": AlgorithmConfig(path = "ntruhps4096821", is_kem = True),
    "ntruhrss701": AlgorithmConfig(path = "ntruhrss701", is_kem = True),
    "saber": AlgorithmConfig(path = "saber", is_kem = True),
    "hqc128": AlgorithmConfig(path = "hqc128", is_kem = True,
                            extra_header = HQC128_HEADER),
    "hqc192": AlgorithmConfig(path = "hqc192", is_kem = True,
                            extra_header = HQC192_HEADER),
    "hqc256": AlgorithmConfig(path = "hqc256", is_kem = True,
                            extra_header = HQC256_HEADER),
    "mlkem512": AlgorithmConfig(path = "mlkem512", is_kem = True,
                             extra_header = MLKEM512_HEADER),
    "mlkem768": AlgorithmConfig(path = "mlkem768", is_kem = True,
                             extra_header = MLKEM768_HEADER),
    "mlkem1024": AlgorithmConfig(path = "mlkem1024", is_kem = True,
                              extra_header = MLKEM1024_HEADER
                              ),
    "xwing": AlgorithmConfig(path = "xwing",
                           is_kem =True,
                           extra_sources = ["mlkem/ref"],
                           extra_header = XWING_HEADER,
                           extra_include_dirs = ["mlkem"],
                           extra_library = ["25519"]
                           ),
}