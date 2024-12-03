from dataclasses import dataclass, field
from typing import List, Optional

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
    is_cpp: bool = False
    is_common: bool = True
    is_debug: bool = True
    is_other_include: bool = False
    extra_header: Optional[str] = None
    extra_sources: List[str] = field(default_factory=list)
    extra_include_dirs: List[str] = field(default_factory=list)
    extra_compiler_args: List[str] = field(default_factory=list)
    extra_link_args: List[str] = field(default_factory=list)
    extra_libraries: List[str] = field(default_factory=list)

SUPPORT_ALGORITHMS = []

ALGORITHMS = {
    # common
    "dhkem": AlgorithmConfig(path="dhkem", is_other_include=True, extra_libraries=['25519','sodium']),
    "rsakem": AlgorithmConfig(path="rsakem", is_other_include=True, extra_libraries=['crypto', 'ssl']),
    "eckem": AlgorithmConfig(path="eckem", is_other_include=True, extra_libraries=['crypto', 'ssl']),
    "x25519kem": AlgorithmConfig(path="x5519kem", is_other_include=True, extra_libraries=['crypto', 'ssl']),
    "x448kem": AlgorithmConfig(path="x448kem", is_other_include=True, extra_libraries=['crypto', 'ssl']),

    # post-quantum
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
    "mceliece348864_clean": AlgorithmConfig(path = "mceliece348864-clean", is_common=True),
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
    "mceliece6960119_clean": AlgorithmConfig(path = "mceliece6960119-clean", is_common=True),
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

    # new
    "bike": AlgorithmConfig(path="bike", is_cpp=True, is_common=False, is_other_include=True, extra_libraries=["crypto","ssl","m","dl","ntl","gmp","gf2x", "pthread"]),

    # hybird
    "xwing": AlgorithmConfig(path = "xwing",
                            is_common = False,
                            is_other_include = True,
                            extra_sources = ["mlkem/ref"],
                            # extra_header = True,
                            # extra_include_dirs = ["mlkem"],
                            extra_libraries = ["25519"]
                           ),
    # "tm": AlgorithmConfig(path = "tm",
    #                         is_common=False,
    #                         extra_sources = ["mlkem/ref"],
    #                         extra_header = XWING_HEADER,
    #                         extra_include_dirs = ["mlkem"],
    #                         extra_libraries = ["25519"]
    #                        ),
}