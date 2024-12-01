# pqcrypt
post-quantum cryptography

## Tips
The encrypt/decrypt result is wrong
```cpp
dhkem
mceliece*/mceliece_clean*
ntruhps*
```
The algorithm not implemented
```cpp
bike
ntruhrss701  
frodokem* 
```

## Deps

```shell
sudo apt-get install lib25519-1 lib25519-dev libssl-dev libsodium ...
```

libsodium 1.0.20
```shell
conda remove libsodium --force
```

## Usage

Compile CFFI library for all the algorithms
```shell
python compile.py {algo}
```
or compile all the support algorithms with
```shell
python compile.py
```

Then call the basic API from below:
```cpp
#define cffi_crypto_keygen crypto_kem_keypair
#define cffi_crypto_kem_encaps crypto_kem_enc
#define cffi_crypto_kem_decaps crypto_kem_dec
#define cffi_crypto_encrypt PQCRYPT_crypto_encrypt
#define cffi_crypto_decrypt PQCRYPT_crypto_decrypt

#define CFFI_CRYPTO_ALGNAME        CRYPTO_ALGNAME
#define CFFI_CRYPTO_BYTES          CRYPTO_BYTES
#define CFFI_CRYPTO_CIPHERTEXTBYTES CRYPTO_CIPHERTEXTBYTES
#define CFFI_CRYPTO_PUBLICKEYBYTES  CRYPTO_PUBLICKEYBYTES
#define CFFI_CRYPTO_SECRETKEYBYTES  CRYPTO_SECRETKEYBYTES
#define CFFI_CRYPTO_PLAINTEXTBYTES  CRYPTO_PLAINTEXTBYTES
```
and the interface it's all
```cpp
int cffi_crypto_keygen(uint8_t *pk, uint8_t *sk);
int cffi_crypto_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int cffi_crypto_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int cffi_crypto_encrypt(uint8_t *ct, uint8_t *pt, const uint8_t *pk);
int cffi_crypto_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk);
```
the python interface Like below:
```python
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
```
the common usage like:
```python
import pqcrypt.kem.{algo} as algo
pk, sk = algo.keygen()
assert(len(pk) == algo.PUBLIC_KEY_SIZE))
assert(len(sk) == algo.SECRET_KEY_SIZE))
ct, ss = algo.encaps(pk)
assert(len(ct)) == algo.CIPHERTEXT_SIZE))
assert(len(ss)) == algo.SHAREDKEY_SIZE))
ss = algo.decaps(sk, ct)
ct = algo.encrypt(b'a'*algo.PLAINTEXT_SIZE, pk)
pt = algo.decrypt(ciphertext, sk)
```

All the `keygen`, `encaps`, `decaps`, `encrypt` and `decrypt` all call from {algo}.so and native speed.

## Support algorithms
### post quantum algorithms
firesaber  

kyber1024  
kyber1024_90s  
kyber512  
kyber512_90s  
kyber768  
kyber768_90s  
lightsaber  
mceliece348864  
mceliece348864f  
mceliece460896  
mceliece460896f  
mceliece6688128  
mceliece6688128f  
mceliece6960119  
mceliece6960119f  
mceliece8192128  
mceliece8192128f  
ntruhps2048509  
ntruhps2048677  
ntruhps4096821  

saber  
sntrup761_clean from liboqs  
hqc128  
hqc192  
hqc256  
mlkem512  
mlkem768  
mlkem1024  

### common algorithms
rsakem  
dhkem(x25519)  
eckem  

## Will support in the future
bike  
frodokem1344aes  
frodokem1344shake  
frodokem640aes  
frodokem640shake  
frodokem976aes  
frodokem976shake  
ntruhrss701  


## Migrate your own algorithm

All the Python with C interface is head with "CFFI/cffi"

## Thanks
https://github.com/kpdemetriou/pqcrypto  
https://github.com/PQClean/PQClean  
https://github.com/X-Wing-KEM-Team/xwing  
https://github.com/open-quantum-safe/liboqs
