# pqcrypt
post-quantum cryptography

## Deps

```shell
sudo apt-get install xxxx-dev
lib25519
libssl
```

## Usage

Compile CFFI library for all the algorithms
```shell
python compile.py
```
Then call the basic API from below:
```c
crypto_kem_keypair
crypto_kem_enc
crypto_kem_dec
```
Like
```python
from pqcrypt.kem.{algorithm} import generate_keypair, encrypt, decrypt

public_key, secret_key = generate_keypair()
ciphertext, plaintext_original = encrypt(public_key)
plaintext_recovered = decrypt(secret_key, ciphertext)
```

All the `generate_keypair`, `encrypt` and `decrypt` all call from .so and native speed.

## Support algorithms
firesaber  
frodokem1344aes  
frodokem1344shake  
frodokem640aes  
frodokem640shake  
frodokem976aes  
frodokem976shake  
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
ntruhrss701  
saber  
hqc128  
hqc192  
hqc256  
mlkem512  
mlkem768  
mlkem1024  
xwing  

## Thanks
https://github.com/kpdemetriou/pqcrypto  
https://github.com/PQClean/PQClean  
https://github.com/X-Wing-KEM-Team/xwing  

