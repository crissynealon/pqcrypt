import os
import sys
import platform
from cffi import FFI
from pathlib import Path
from algorithms import AlgorithmConfig, ALGORITHMS, SUPPORT_ALGORITHMS

# for debuggging
import ipdb
import IPython

PATH_ROOT = Path(__file__).parent
PATH_SOURCES = os.path.join(PATH_ROOT, "algos")
PATH_COMMON = os.path.join(PATH_SOURCES,"common")

IS_WINDOWS, IS_LINUX, IS_MACOS = (lambda s: (s == "Windows", s == "Linux", s == "Darwin"))(platform.system())

BASIC_DEFINITIONS_KEM = """
    int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
    int crypto_kem_enc(uint8_t *c, uint8_t *key, const uint8_t *pk);
    int crypto_kem_dec(uint8_t *key, const uint8_t *c, const uint8_t *sk);

    #define CRYPTO_PUBLICKEYBYTES ...
    #define CRYPTO_SECRETKEYBYTES ...
    #define CRYPTO_CIPHERTEXTBYTES ...
    #define CRYPTO_BYTES ...
"""

# different kem xwing from https://github.com/X-Wing-KEM-Team/xwing add derand
EXTRA_DEFINITIONS_KEM = """
    int crypto_keypair(uint8_t *pk, uint8_t *sk);
    int crypto_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int crypto_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
    int crypto_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
    int crypto_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

    #define CRYPTO_PUBLICKEYBYTES ...
    #define CRYPTO_SECRETKEYBYTES ...
    #define CRYPTO_CIPHERTEXTBYTES ...
    #define CRYPTO_BYTES ...
    #define CRYPTO_KEYPAIRCOINBYTES ...
    #define CRYPTO_ENCCOINBYTES ...
"""


def create_algorithm_ffi(name, algorithm):
    """
    name: name,
    algorithm: AlgorithmConfig
    """
    if hasattr(algorithm, "is_kem") and not algorithm.is_kem:
        raise SystemError("Algorithm must be KEM")

    if hasattr(algorithm, "path") and algorithm.path:
        algorithm_path = os.path.join(PATH_SOURCES, algorithm.path)
        if not os.path.isdir:
            raise SystemError("Algorithm source path is wrong")
    else:
        raise SystemError("Algorithm source path must be set")

    include_dirs, compiler_args, link_args, libraries = [], [], [], []

    if IS_WINDOWS:
        compiler_args += ["/O2", "/nologo"]
        link_args.append("/NODEFAULTLIB:MSVCRTD")
        libraries.append("advapi32")

        raise SystemExit("Windows have not supported now!")

    elif IS_LINUX:
        # CFLAGS=-O3 -Wall -Wextra -Wpedantic -Wshadow -Wvla -Werror -Wredundant-decls -Wmissing-prototypes -std=c99
        compiler_args +=["-O3",
                        "-std=c99",
                        "-Wall",
                        "-Wextra",
                        "-Wno-pedantic",
                        "-Wvla",
                        "-Wredundant-decls",
                        "-Wmissing-prototypes",
                        "-Wno-unused-result"]
        # add common include headers
        # include_dirs.append(str(PATH_COMMON))
    elif IS_MACOS:
        raise SystemExit("MacOS have not implemented yet!")
    else:
        raise SystemError("Don't know your platform?")

    # "ref" is a standard path in NIST
    src = os.path.join(algorithm_path , "ref")
    # "api.h" is also a standard header for algorithm
    api = os.path.join(src , "api.h")

    ffi = FFI()
    ffi.cdef(BASIC_DEFINITIONS_KEM)

    # ipdb.set_trace()
    src_files = [str(file) for file in Path(src).glob("*.c") if file.is_file()]
    # common_files = [str(file) for file in Path(PATH_COMMON).glob("*.c") if file.is_file()]

    header = ""
    if hasattr(algorithm, "extra_header") and algorithm.extra_header:
        header = f'#include "{str(api)}"' + algorithm.extra_header
    else:
        header = f'#include "{str(api)}"'

    # import ipdb; ipdb.set_trace();
    sources = [str(file) for file in src_files]
    if hasattr(algorithm, "extra_sources") and algorithm.extra_sources:
        extra_sources = [os.path.join(src,dir) for dir in algorithm.extra_sources]
        for dir in extra_sources:
           sources.extend([str(file) for file in Path(dir).glob("*.c") if file.is_file()])

    if hasattr(algorithm, "extra_include_dirs") and algorithm.extra_include_dirs:
        include_dirs = list(set(include_dirs).union(algorithm.extra_include_dirs))
        include_dirs = [os.path.join(src,dir) for dir in include_dirs]
        include_dirs.append("/usr/include")

    if hasattr(algorithm, "extra_compile_args") and algorithm.extra_compile_args:
        compiler_args = list(set(compiler_args).union(algorithm.extra_compile_args))

    if hasattr(algorithm, "extra_link_args") and algorithm.extra_link_args:
        link_args = list(set(link_args).union(algorithm.extra_link_args))

    if hasattr(algorithm, "extra_libraries") and algorithm.extra_libraries:
        libraries = list(set(libraries).union(algorithm.extra_libraries))

    # Only support POSIX pure C implementation
    print("include_dirs", include_dirs)
    print(header)
    ffi.set_source(
        f"pqcrypt._kem.{name}",
        header,
        sources=sources,
        include_dirs=include_dirs,
        extra_compile_args=compiler_args,
        extra_link_args=link_args,
        libraries=libraries,
        library_dirs=["/usr/lib"],
        source_extension='.c'
    )

    return ffi

if __name__ == "__main__":
    if len(sys.argv) == 1:
        for name, algo in ALGORITHMS.items():
            algorithm_ffi = create_algorithm_ffi(name, algo)
            globals()[f"{name}_ffi"] = algorithm_ffi
            globals()[f"{name}_ffi"].compile(verbose=True)
    elif len(sys.argv) == 2:
        name = sys.argv[1]
        try:
            algo = ALGORITHMS[name]
        except KeyError:
            raise SystemError(f"Unknow algorithm {name}")
        algorithm_ffi = create_algorithm_ffi(name, algo)
        globals()[f"{name}_ffi"] = algorithm_ffi
        globals()[f"{name}_ffi"].compile(verbose=True)
    else:
        print("Usage: python compile [xwing]")
        print("Support algorithms:")
        print(SUPPORT_ALGORITHMS)