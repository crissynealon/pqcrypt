from binascii import hexlify


def firesaber():
    import pqcrypt.kem.firesaber as firesaber

    print('firesaber')
    pk, sk = firesaber.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = firesaber.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = firesaber.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    ciphertext = firesaber.encrypt(b'a'*firesaber.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = firesaber.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*firesaber.PLAINTEXT_SIZE)


def hqc128():
    import pqcrypt.kem.hqc128 as hqc128
    print('hqc128')
    pk, sk = hqc128.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = hqc128.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = hqc128.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", hqc128.PLAINTEXT_SIZE)

    ciphertext = hqc128.encrypt(b'a'*hqc128.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = hqc128.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*hqc128.PLAINTEXT_SIZE)


def hqc192():
    import pqcrypt.kem.hqc192 as hqc192
    print('hqc192')
    pk, sk = hqc192.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = hqc192.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = hqc192.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", hqc192.PLAINTEXT_SIZE)

    ciphertext = hqc192.encrypt(b'a'*hqc192.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = hqc192.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*hqc192.PLAINTEXT_SIZE)


def hqc256():
    import pqcrypt.kem.hqc256 as hqc256
    print('hqc256')
    pk, sk = hqc256.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = hqc256.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = hqc256.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", hqc256.PLAINTEXT_SIZE)

    ciphertext = hqc256.encrypt(b'a'*hqc256.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = hqc256.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*hqc256.PLAINTEXT_SIZE)


def saber():
    import pqcrypt.kem.saber as saber

    print('saber')
    pk, sk = saber.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = saber.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = saber.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    ciphertext = saber.encrypt(b'a'*saber.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = saber.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*saber.PLAINTEXT_SIZE)


def lightsaber():
    import pqcrypt.kem.firesaber as lightsaber

    print('lightsaber')
    pk, sk = lightsaber.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = lightsaber.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = lightsaber.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    ciphertext = lightsaber.encrypt(b'a'*lightsaber.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = lightsaber.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*lightsaber.PLAINTEXT_SIZE)


def mlkem512():
    import pqcrypt.kem.mlkem512 as mlkem512

    print('mlkem512')
    pk, sk = mlkem512.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mlkem512.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mlkem512.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    ciphertext = mlkem512.encrypt(b'a'*mlkem512.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mlkem512.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*mlkem512.PLAINTEXT_SIZE)


def mlkem768():
    import pqcrypt.kem.mlkem768 as mlkem768

    print('mlkem768')
    pk, sk = mlkem768.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mlkem768.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mlkem768.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    ciphertext = mlkem768.encrypt(b'a'*mlkem768.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mlkem768.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*mlkem768.PLAINTEXT_SIZE)


def mlkem1024():
    import pqcrypt.kem.mlkem1024 as mlkem1024

    print('mlkem1024')
    pk, sk = mlkem1024.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mlkem1024.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mlkem1024.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    ciphertext = mlkem1024.encrypt(b'a'*mlkem1024.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mlkem1024.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*mlkem1024.PLAINTEXT_SIZE)


def kyber512():
    import pqcrypt.kem.kyber512 as kyber512

    print('kyber512')
    pk, sk = kyber512.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = kyber512.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = kyber512.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    ciphertext = kyber512.encrypt(b'a'*kyber512.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = kyber512.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*kyber512.PLAINTEXT_SIZE)


def kyber512_90s():
    import pqcrypt.kem.kyber512_90s as kyber512_90s

    print('kyber512_90s')
    pk, sk = kyber512_90s.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = kyber512_90s.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = kyber512_90s.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    ciphertext = kyber512_90s.encrypt(b'a'*kyber512_90s.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = kyber512_90s.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*kyber512_90s.PLAINTEXT_SIZE)


def kyber768():
    import pqcrypt.kem.kyber768 as kyber768

    print('kyber768')
    pk, sk = kyber768.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = kyber768.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = kyber768.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    ciphertext = kyber768.encrypt(b'a'*kyber768.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = kyber768.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*kyber768.PLAINTEXT_SIZE)


def kyber768_90s():
    import pqcrypt.kem.kyber768_90s as kyber768_90s

    print('kyber768_90s')
    pk, sk = kyber768_90s.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = kyber768_90s.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = kyber768_90s.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    ciphertext = kyber768_90s.encrypt(b'a'*kyber768_90s.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = kyber768_90s.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*kyber768_90s.PLAINTEXT_SIZE)


def kyber1024_90s():
    import pqcrypt.kem.kyber1024_90s as kyber1024_90s

    print('kyber1024_90s')
    pk, sk = kyber1024_90s.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = kyber1024_90s.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = kyber1024_90s.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    ciphertext = kyber1024_90s.encrypt(b'a'*kyber1024_90s.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = kyber1024_90s.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*kyber1024_90s.PLAINTEXT_SIZE)


def kyber1024():
    import pqcrypt.kem.kyber1024 as kyber1024

    print('kyber1024')
    pk, sk = kyber1024.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = kyber1024.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = kyber1024.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    ciphertext = kyber1024.encrypt(b'a'*kyber1024.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = kyber1024.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    assert(plaintext == b'a'*kyber1024.PLAINTEXT_SIZE)


def ntruhps2048509():
    import pqcrypt.kem.ntruhps2048509 as ntruhps2048509

    print('ntruhps2048509')
    pk, sk = ntruhps2048509.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = ntruhps2048509.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = ntruhps2048509.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", ntruhps2048509.PLAINTEXT_SIZE)

    ciphertext = ntruhps2048509.encrypt(b'a'*ntruhps2048509.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = ntruhps2048509.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

    # assert(plaintext == b'a'*ntruhps2048509.PLAINTEXT_SIZE)


def ntruhps2048677():
    import pqcrypt.kem.ntruhps2048677 as ntruhps2048677

    print('ntruhps2048677')
    pk, sk = ntruhps2048677.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = ntruhps2048677.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = ntruhps2048677.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", ntruhps2048677.PLAINTEXT_SIZE)

    ciphertext = ntruhps2048677.encrypt(b'a'*ntruhps2048677.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = ntruhps2048677.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))


def ntruhps4096821():
    import pqcrypt.kem.ntruhps4096821 as ntruhps4096821

    print('ntruhps2048677')
    pk, sk = ntruhps4096821.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = ntruhps4096821.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = ntruhps4096821.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", ntruhps4096821.PLAINTEXT_SIZE)

    ciphertext = ntruhps4096821.encrypt(b'a'*ntruhps4096821.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = ntruhps4096821.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))


def ntruhrss701():
    import pqcrypt.kem.ntruhrss701 as ntruhrss701

    print('ntruhrss701')
    pk, sk = ntruhrss701.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = ntruhrss701.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = ntruhrss701.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", ntruhrss701.PLAINTEXT_SIZE)

    ciphertext = ntruhrss701.encrypt(b'a'*ntruhrss701.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = ntruhrss701.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

def mceliece348864():
    import pqcrypt.kem.mceliece348864 as mceliece348864

    print('mceliece348864')
    pk, sk = mceliece348864.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mceliece348864.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mceliece348864.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", mceliece348864.PLAINTEXT_SIZE)

    ciphertext = mceliece348864.encrypt(b'a'*mceliece348864.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mceliece348864.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

def mceliece348864_clean():
    import pqcrypt.kem.mceliece348864_clean as mceliece348864

    print('mceliece348864')
    pk, sk = mceliece348864.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mceliece348864.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mceliece348864.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", mceliece348864.PLAINTEXT_SIZE)

    ciphertext = mceliece348864.encrypt(b'a'*mceliece348864.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mceliece348864.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

def mceliece348864f_clean():
    import pqcrypt.kem.mceliece348864_clean as mceliece348864f

    print('mceliece348864f')
    pk, sk = mceliece348864f.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mceliece348864f.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mceliece348864f.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", mceliece348864f.PLAINTEXT_SIZE)

    ciphertext = mceliece348864f.encrypt(b'a'*mceliece348864f.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mceliece348864f.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

def mceliece460896_clean():
    import pqcrypt.kem.mceliece460896_clean as mceliece460896

    print('mceliece460896')
    pk, sk = mceliece460896.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mceliece460896.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mceliece460896.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", mceliece460896.PLAINTEXT_SIZE)

    ciphertext = mceliece460896.encrypt(b'a'*mceliece460896.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mceliece460896.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

def mceliece460896f_clean():
    import pqcrypt.kem.mceliece460896f_clean as mceliece460896f

    print('mceliece460896f')
    pk, sk = mceliece460896f.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mceliece460896f.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mceliece460896f.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", mceliece460896f.PLAINTEXT_SIZE)

    ciphertext = mceliece460896f.encrypt(b'a'*mceliece460896f.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mceliece460896f.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

def mceliece6688128_clean():
    import pqcrypt.kem.mceliece6688128_clean as mceliece6688128

    print('mceliece6688128')
    pk, sk = mceliece6688128.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mceliece6688128.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mceliece6688128.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", mceliece6688128.PLAINTEXT_SIZE)

    ciphertext = mceliece6688128.encrypt(b'a'*mceliece6688128.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mceliece6688128.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

def mceliece6688128f_clean():
    import pqcrypt.kem.mceliece6688128f_clean as mceliece6688128f

    print('mceliece6688128f')
    pk, sk = mceliece6688128f.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mceliece6688128f.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mceliece6688128f.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", mceliece6688128f.PLAINTEXT_SIZE)

    ciphertext = mceliece6688128f.encrypt(b'a'*mceliece6688128f.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mceliece6688128f.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

def mceliece6960119_clean():
    import pqcrypt.kem.mceliece6960119_clean as mceliece6960119

    print('mceliece6960119')
    pk, sk = mceliece6960119.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mceliece6960119.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mceliece6960119.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", mceliece6960119.PLAINTEXT_SIZE)

    ciphertext = mceliece6960119.encrypt(b'a'*mceliece6960119.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mceliece6960119.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

def mceliece6960119f_clean():
    import pqcrypt.kem.mceliece6960119f_clean as mceliece6960119f

    print('mceliece6960119f')
    pk, sk = mceliece6960119f.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mceliece6960119f.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mceliece6960119f.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", mceliece6960119f.PLAINTEXT_SIZE)

    ciphertext = mceliece6960119f.encrypt(b'a'*mceliece6960119f.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mceliece6960119f.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

def mceliece8192128_clean():
    import pqcrypt.kem.mceliece8192128_clean as mceliece8192128

    print('mceliece8192128')
    pk, sk = mceliece8192128.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mceliece8192128.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mceliece8192128.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", mceliece8192128.PLAINTEXT_SIZE)

    ciphertext = mceliece8192128.encrypt(b'a'*mceliece8192128.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mceliece8192128.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

def mceliece8192128f_clean():
    import pqcrypt.kem.mceliece8192128f_clean as mceliece8192128f

    print('mceliece8192128f')
    pk, sk = mceliece8192128f.keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = mceliece8192128f.encaps(pk)
    print("ss", hexlify(ss))

    ss0 = mceliece8192128f.decaps(sk, ct)
    print("ss0", hexlify(ss0))

    assert(ss0 == ss)

    print("PLAINTEXT_SIZE: ", mceliece8192128f.PLAINTEXT_SIZE)

    ciphertext = mceliece8192128f.encrypt(b'a'*mceliece8192128f.PLAINTEXT_SIZE, pk)
    print("cipher", hexlify(ciphertext))

    plaintext = mceliece8192128f.decrypt(ciphertext, sk)
    print("plain", hexlify(plaintext))

def main():
    import pqcrypt.kem as kem
    print(kem.firesaber.PUBLIC_KEY_SIZE)
    print(kem.saber.SHAREDKEY_SIZE)

    print(kem.mceliece348864.SECRET_KEY_SIZE)
    print(kem.mceliece460896f.PLAINTEXT_SIZE)

if __name__ == "__main__":
    ## Saber
    # firesaber()
    # lightsaber()
    # saber()

    ## HQC
    # hqc128()
    # hqc192()
    # hqc256()

    ## kyber/mlkem
    # mlkem512()
    # mlkem768()
    # mlkem1024()

    # kyber512()
    # kyber512_90s()
    # kyber768()
    # kyber768_90s()
    # kyber1024()
    # kyber1024_90s()

    ## mcelience
    # mceliece348864()
    # mceliece348864f()
    # mceliece460896()
    # mceliece460896f()
    # mceliece6688128()
    # mceliece6688128f()
    # mceliece6960119()
    # mceliece6960119f()
    # mceliece8192128()
    # mceliece8192128f()
    # mceliece348864_clean()
    # mceliece348864f_clean()
    # mceliece460896_clean()
    # mceliece460896f_clean()
    # mceliece6688128_clean()
    # mceliece6688128f_clean()
    # mceliece6960119_clean()
    # mceliece6960119f_clean()
    # mceliece8192128_clean()
    # mceliece8192128f_clean()


    ## ntruhps
    # ntruhps2048509()
    # ntruhps2048677()
    # ntruhps4096821()
    # ntruhrss701()

    ## fordokem
    # fordokem640aes()
    # fordokem640shake()
    # fordokem976aes()
    # fordokem976shake()
    # fordokem1344aes()
    # fordokem1344shake()

    ## sntryp
    # sntryp761()

    ## bike
    # bike()
    # main()

