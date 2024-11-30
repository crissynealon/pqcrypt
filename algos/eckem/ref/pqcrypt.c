#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/provider.h>
#include "pqcrypt.h"

// EC-KEM encryption function


int PQCRYPT_eckem_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk) {
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) return -1;

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *peer_key = NULL;
    EC_KEY *ec_key = NULL;
    EC_KEY *peer_ec_key = NULL;
    const EC_GROUP *group = NULL;
    EC_POINT *pub_point = NULL;
    int ret = -1;
    uint8_t shared_key[32];

    // Create EC key structures
    if (!(ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) ||
        !(peer_ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) ||
        !(group = EC_KEY_get0_group(ec_key)) ||
        !(pub_point = EC_POINT_new(group))) {
        goto cleanup;
    }

    // Import peer's public key
    if (!EC_POINT_oct2point(group, pub_point, pk, PQCRYPT_CRYPTO_PUBLICKEYBYTES, NULL) ||
        !EC_KEY_set_public_key(peer_ec_key, pub_point)) {
        goto cleanup;
    }

    // Generate ephemeral key pair
    if (!EC_KEY_generate_key(ec_key)) {
        goto cleanup;
    }

    // Create EVP_PKEY for our ephemeral key
    if (!(pkey = EVP_PKEY_new()) ||
        !EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        goto cleanup;
    }
    ec_key = NULL;

    // Create EVP_PKEY for peer's public key
    if (!(peer_key = EVP_PKEY_new()) ||
        !EVP_PKEY_assign_EC_KEY(peer_key, peer_ec_key)) {
        goto cleanup;
    }
    peer_ec_key = NULL;

    // Setup key derivation to get shared secret
    if (!(kctx = EVP_PKEY_CTX_new(pkey, NULL)) ||
        EVP_PKEY_derive_init(kctx) <= 0 ||
        EVP_PKEY_derive_set_peer(kctx, peer_key) <= 0) {
        goto cleanup;
    }

    // Derive shared secret
    size_t shared_key_len = sizeof(shared_key);
    if (EVP_PKEY_derive(kctx, shared_key, &shared_key_len) <= 0) {
        goto cleanup;
    }

    // Export ephemeral public key into first part of ciphertext
    if (!EC_POINT_point2oct(group,
                         EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(pkey)),
                         POINT_CONVERSION_COMPRESSED,
                         ct, 33, NULL)) {
        goto cleanup;
    }

    // XOR the plaintext with shared secret for the actual encryption
    for(int i = 0; i < PQCRYPT_CRYPTO_BYTES; i++) {
        ct[33 + i] = pt[i] ^ shared_key[i];
    }

    ret = 0;

cleanup:
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peer_key);
    EC_POINT_free(pub_point);
    if (ec_key) EC_KEY_free(ec_key);
    if (peer_ec_key) EC_KEY_free(peer_ec_key);
    OSSL_PROVIDER_unload(defprov);
    return ret;
}

int PQCRYPT_eckem_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk) {
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) return -1;

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *our_key = NULL;
    EVP_PKEY *peer_key = NULL;
    EC_KEY *our_ec_key = NULL;
    EC_KEY *peer_ec_key = NULL;
    EC_POINT *peer_point = NULL;
    int ret = -1;
    uint8_t shared_key[32];

    // Create EC key structures
    if (!(our_ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) ||
        !(peer_ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) {
        goto cleanup;
    }

    // Import private key
    BIGNUM *priv_bn = BN_bin2bn(sk, PQCRYPT_CRYPTO_SECRETKEYBYTES, NULL);
    if (!priv_bn || !EC_KEY_set_private_key(our_ec_key, priv_bn)) {
        if (priv_bn) BN_free(priv_bn);
        goto cleanup;
    }
    BN_free(priv_bn);

    // Get peer's ephemeral public key from first part of ciphertext
    const EC_GROUP *group = EC_KEY_get0_group(peer_ec_key);
    peer_point = EC_POINT_new(group);

    if (!peer_point) {
        goto cleanup;
    }

    // Import peer's public key from first 33 bytes of ciphertext
    if (!EC_POINT_oct2point(group, peer_point, ct, 33, NULL)) {
        goto cleanup;
    }

    if (!EC_KEY_set_public_key(peer_ec_key, peer_point)) {
        goto cleanup;
    }

    // Convert to EVP_PKEY format
    if (!(our_key = EVP_PKEY_new()) || !EVP_PKEY_assign_EC_KEY(our_key, our_ec_key)) {
        goto cleanup;
    }
    our_ec_key = NULL;

    if (!(peer_key = EVP_PKEY_new()) || !EVP_PKEY_assign_EC_KEY(peer_key, peer_ec_key)) {
        goto cleanup;
    }
    peer_ec_key = NULL;

    // Setup key derivation
    if (!(kctx = EVP_PKEY_CTX_new(our_key, NULL)) ||
        EVP_PKEY_derive_init(kctx) <= 0 ||
        EVP_PKEY_derive_set_peer(kctx, peer_key) <= 0) {
        goto cleanup;
    }

    // Derive the same shared secret
    size_t shared_key_len = sizeof(shared_key);
    if (EVP_PKEY_derive(kctx, shared_key, &shared_key_len) <= 0) {
        goto cleanup;
    }

    // XOR the encrypted part with shared secret to decrypt
    for(int i = 0; i < PQCRYPT_CRYPTO_BYTES; i++) {
        pt[i] = ct[33 + i] ^ shared_key[i];
    }

    ret = 0;

cleanup:
    if (kctx) EVP_PKEY_CTX_free(kctx);
    if (our_key) EVP_PKEY_free(our_key);
    if (peer_key) EVP_PKEY_free(peer_key);
    if (peer_point) EC_POINT_free(peer_point);
    if (our_ec_key) EC_KEY_free(our_ec_key);
    if (peer_ec_key) EC_KEY_free(peer_ec_key);
    if (defprov) OSSL_PROVIDER_unload(defprov);
    return ret;
}