from binascii import hexlify
# from pqcrypt.kem.tm import generate_keypair, encrypt, decrypt
from pqcrypt.kem.firesaber import keygen, encaps, decaps

def firesaber():
    pk, sk = keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = encaps(pk)
    print("ss", hexlify(ss))

    ss0 = decaps(sk, ct)
    print("ss0", hexlify(ss0))

def hqc128():
    pk, sk = keygen()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))

    ct, ss = encaps(pk)
    print("ss", hexlify(ss))

    ss0 = decaps(sk, ct)
    print("ss0", hexlify(ss0))

def main():
    pk, sk = generate_keypair()
    print("pk", hexlify(pk))
    print("sk", hexlify(sk))
    ct, ss = encrypt(pk)
    print("ss", hexlify(ss))
    ss0 = decrypt(sk, ct)
    print('ss0', hexlify(ss0))

if __name__ == "__main__":
    # main()
    # firesaber()
    hqc128()
