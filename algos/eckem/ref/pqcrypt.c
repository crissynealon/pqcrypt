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
    EC_KEY *ec_key = NULL;
    const EC_GROUP *group = NULL;
    EC_POINT *pub_point = NULL;
    int ret = -1;

    if (!(ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) ||
        !(group = EC_KEY_get0_group(ec_key)) ||
        !(pub_point = EC_POINT_new(group))) {
        goto cleanup;
    }

    if (!EC_POINT_oct2point(group, pub_point, pk, PQCRYPT_CRYPTO_PUBLICKEYBYTES, NULL) ||
        !EC_KEY_set_public_key(ec_key, pub_point)) {
        goto cleanup;
    }

    if (!EC_KEY_generate_key(ec_key)) {
        goto cleanup;
    }

    if (!(pkey = EVP_PKEY_new()) ||
        !EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        goto cleanup;
    }
    ec_key = NULL; // EVP_PKEY now owns the EC_KEY

    if (!(kctx = EVP_PKEY_CTX_new(pkey, NULL)) ||
        EVP_PKEY_derive_init(kctx) <= 0) {
        goto cleanup;
    }

    size_t ct_len = PQCRYPT_CRYPTO_CIPHERTEXTBYTES;
    if (!EC_POINT_point2oct(group, EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(pkey)),
                           POINT_CONVERSION_COMPRESSED, ct, ct_len, NULL)) {
        goto cleanup;
    }

    size_t ss_len = PQCRYPT_CRYPTO_BYTES;
    if (EVP_PKEY_derive(kctx, pt, &ss_len) <= 0) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(pkey);
    EC_POINT_free(pub_point);
    if (ec_key) EC_KEY_free(ec_key);
    OSSL_PROVIDER_unload(defprov);
    return ret;
}

int PQCRYPT_eckem_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk) {
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) return -1;

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    EC_POINT *pub_point = NULL;
    const EC_GROUP *group = NULL;
    int ret = -1;

    if (!(ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) ||
        !EC_KEY_oct2priv(ec_key, sk, PQCRYPT_CRYPTO_SECRETKEYBYTES) ||
        !(group = EC_KEY_get0_group(ec_key)) ||
        !(pub_point = EC_POINT_new(group))) {
        goto cleanup;
    }

    if (!EC_POINT_oct2point(group, pub_point, ct, PQCRYPT_CRYPTO_CIPHERTEXTBYTES, NULL) ||
        !EC_KEY_set_public_key(ec_key, pub_point)) {
        goto cleanup;
    }

    if (!(pkey = EVP_PKEY_new()) ||
        !EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        goto cleanup;
    }
    ec_key = NULL; // EVP_PKEY now owns the EC_KEY

    if (!(kctx = EVP_PKEY_CTX_new(pkey, NULL)) ||
        EVP_PKEY_derive_init(kctx) <= 0) {
        goto cleanup;
    }

    size_t pt_len = PQCRYPT_CRYPTO_BYTES;
    if (EVP_PKEY_derive(kctx, pt, &pt_len) <= 0) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(pkey);
    EC_POINT_free(pub_point);
    if (ec_key) EC_KEY_free(ec_key);
    OSSL_PROVIDER_unload(defprov);
    return ret;
}