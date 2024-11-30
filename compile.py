import os
import sys
import platform
from cffi import FFI
from pathlib import Path
from algorithms import ALGORITHMS, SUPPORT_ALGORITHMS

# for debuggging
import ipdb
import IPython

PATH_ROOT = os.path.dirname(os.path.abspath(__file__))
PATH_SOURCES = os.path.join(PATH_ROOT, "algos")
PATH_COMMON = os.path.join(PATH_SOURCES,"common")

IS_WINDOWS, IS_LINUX, IS_MACOS = (lambda s: (s == "Windows", s == "Linux", s == "Darwin"))(platform.system())

# NOTICE: Our python interface is headwith "cffi/CFFI"
DEFINITIONS = """
    int cffi_crypto_keygen(uint8_t *pk, uint8_t *sk);
    int cffi_crypto_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int cffi_crypto_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
    int cffi_crypto_encrypt(uint8_t *ct, uint8_t *pt, const uint8_t *pk);
    int cffi_crypto_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk);

    #define CFFI_CRYPTO_PUBLICKEYBYTES ...
    #define CFFI_CRYPTO_SECRETKEYBYTES ...
    #define CFFI_CRYPTO_CIPHERTEXTBYTES ...
    #define CFFI_CRYPTO_PLAINTEXTBYTES ...
    #define CFFI_CRYPTO_BYTES ...
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
        if not os.path.isdir(algorithm_path):
            raise SystemError("Algorithm source folder is wrong")
    else:
        raise SystemError("Algorithm source path must be set")

    include_dirs, compiler_args, link_args, libraries = [], [], [], []

    if IS_WINDOWS:
        compiler_args += ["/O2", "/nologo"]
        link_args.append("/NODEFAULTLIB:MSVCRTD")
        libraries.append("advapi32")

        raise SystemExit("Windows have not supported now!")

    elif IS_LINUX:
        # the GCC compiler arguments are from PQClean
        # CFLAGS=-O3 -Wall -Wextra -Wpedantic -Wshadow -Wvla -Werror -Wredundant-decls -Wmissing-prototypes -std=c99
        compiler_args +=["-O3", "-g",
                        # "-std=c99",
                        "-nostdinc++",
                        # "-stdlib=libstdc++",
                        "-Wall",
                        "-Wextra",
                        "-Wpedantic",
                        "-Wvla",
                        "-Wredundant-decls",
                        "-Wmissing-prototypes",
                        "-Wl,--no-as-needed",
                        "-Wunused-result",
                        "-DOPENSSL_API_COMPAT=0x30000000L",
                        # "-DNIST_RAND=1",
                        "-Wl,-rpath=/usr/local/lib64"
                        ]
    elif IS_MACOS:
        raise SystemExit("MacOS have not implemented yet!")
    else:
        raise SystemError("Don't know your platform?")

    # "ref" is a standard implementation refer from NIST
    src = os.path.join(algorithm_path , "ref")

    # "pqcrypt.h" is our standard header for python interface
    pqcrypth = os.path.join(src , "pqcrypt.h")

    ffi = FFI()
    ffi.cdef(DEFINITIONS)

    # if hasattr(algorithm, "is_cpp") and algorithm.is_cpp:
    #     header = '''
    #     #ifdef __cplusplus
    #     extern "C" {
    #     #endif

    #     #include "pqcrypt.h"

    #     #ifdef __cplusplus
    #     }
    #     #endif
    #     '''
    # else:
    header = f'#include "{pqcrypth}"'

    if hasattr(algorithm, "extra_header") and algorithm.extra_header:
        header += algorithm.extra_header

    header += f"""
    PyMODINIT_FUNC PyInit_{name}(void);
    """
    # FIXME: Do not use absolute path
    src_files = [os.path.relpath(str(file), os.getcwd()) for file in Path(src).glob("*.c") if file.is_file()]
    if hasattr(algorithm, "is_cpp") and algorithm.is_cpp:
        src_files.extend([os.path.relpath(str(file), os.getcwd()) for file in Path(src).glob("*.cpp") if file.is_file()])
    common_files = [os.path.relpath(str(file), os.getcwd()) for file in Path(PATH_COMMON).glob("*.c") if file.is_file()]

    if hasattr(algorithm, "is_common") and algorithm.is_common:
        sources = [str(file) for file in (*common_files, *src_files)]
    else:
        sources = [str(file) for file in src_files]

    if hasattr(algorithm, "extra_sources") and algorithm.extra_sources:
        extra_sources = [os.path.join(src,d) for d in algorithm.extra_sources]
        for d in extra_sources:
           sources.extend([os.path.relpath(str(file), os.getcwd()) for file in Path(d).glob("*.c") if file.is_file()])

    include_dirs = [src]
    if hasattr(algorithm, "is_other_include") and algorithm.is_other_include:
        # FIXME: need some others libraries, e.g. lib25519, libsodium, libssl, libcrypt
        include_dirs.append("/usr/include")
        include_dirs.append("/usr/local/include")
        # include_dirs.append("/usr/include/c++/13")
        # include_dirs.append("/usr/include/x86_64-linux-gnu/c++/13")

    if hasattr(algorithm, "extra_include_dirs") and algorithm.extra_include_dirs:
        include_dirs = list(set(include_dirs).union(algorithm.extra_include_dirs))
        include_dirs = [os.path.join(PATH_COMMON,d) for d in include_dirs]

    if hasattr(algorithm, "is_common") and algorithm.is_common:
        include_dirs.append(PATH_COMMON)

    if hasattr(algorithm, "extra_compile_args") and algorithm.extra_compile_args:
        compiler_args = list(set(compiler_args).union(algorithm.extra_compile_args))

    if hasattr(algorithm, "extra_link_args") and algorithm.extra_link_args:
        link_args = list(set(link_args).union(algorithm.extra_link_args))

    if hasattr(algorithm, "extra_libraries") and algorithm.extra_libraries:
        libraries = list(set(libraries).union(algorithm.extra_libraries))

    if hasattr(algorithm, "is_cpp") and algorithm.is_cpp:
        os.environ['CXX'] = 'x86_64-conda-linux-gnu-c++'
        os.environ['CC'] = 'x86_64-conda-linux-gnu-c++'

        # compiler_args.append('-fpermissive')

    print(header)
    # HACKME: Only support POSIX pure C implementation
    ffi.set_source(
        f"pqcrypt._kem.{name}",
        header,
        sources=sources,
        include_dirs=include_dirs,
        extra_compile_args=compiler_args,
        extra_link_args=["-Wl,--no-as-needed"],
        # extra_link_args=link_args,
        libraries=libraries,
        library_dirs=["/usr/local/lib", "/lib/x86_64-linux-gnu/"],
        source_extension='.c'
    )

    return ffi

if __name__ == "__main__":
    if len(sys.argv) == 1:
        for name, algo in ALGORITHMS.items():
            algorithm_ffi = create_algorithm_ffi(name, algo)
            globals()[f"{name}_ffi"] = algorithm_ffi
            try:
                globals()[f"{name}_ffi"].compile(verbose=True)
            except Exception as e:
                print(f"Compilation {name} error: {str(e)}")
    elif len(sys.argv) == 2:
        name = sys.argv[1]
        try:
            algo = ALGORITHMS[name]
        except KeyError:
            raise SystemError(f"Unknow algorithm {name}")
        algorithm_ffi = create_algorithm_ffi(name, algo)
        globals()[f"{name}_ffi"] = algorithm_ffi
        try:
            globals()[f"{name}_ffi"].compile(verbose=True, debug=True)
        except Exception as e:
            print(f"Compilation {name} error: {str(e)}")
    else:
        print("Usage: python compile.py [xwing]")
        print("Support algorithms:")
        print(SUPPORT_ALGORITHMS)
        exit(-1)