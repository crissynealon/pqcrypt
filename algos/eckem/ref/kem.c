#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <string.h>
#include "kem.h"

static int handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    return 1;
}

static EVP_PKEY* generate_ec_key() {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("group", "P-256", 0),
        OSSL_PARAM_END
    };

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}
// Generate keypair for EC-KEM
int PQCRYPT_crypto_eckem_keypair(unsigned char *pk, unsigned char *sk) {
OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) return -1;

    EVP_PKEY *keypair = generate_ec_key();
    if (!keypair) {
        OSSL_PROVIDER_unload(defprov);
        return -1;
    }

    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(keypair);
    if (!ec_key) {
        EVP_PKEY_free(keypair);
        OSSL_PROVIDER_unload(defprov);
        return -1;
    }

    const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    
    size_t pk_len = EC_POINT_point2oct(group, pub_key,
                                      POINT_CONVERSION_COMPRESSED,
                                      pk, PQCRYPT_CRYPTO_PUBLICKEYBYTES, NULL);
    if (pk_len == 0) {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(keypair);
        OSSL_PROVIDER_unload(defprov);
        return -1;
    }

    // 导出私钥
    const BIGNUM *priv_key = EC_KEY_get0_private_key(ec_key);
    if (BN_bn2binpad(priv_key, sk, PQCRYPT_CRYPTO_SECRETKEYBYTES) < 0) {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(keypair);
        OSSL_PROVIDER_unload(defprov);
        return -1;
    }

    EC_KEY_free(ec_key);
    EVP_PKEY_free(keypair);
    OSSL_PROVIDER_unload(defprov);
    return 0;
}

// Encapsulation function
int PQCRYPT_crypto_eckem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) return -1;

    // Create public key from raw bytes
    EVP_PKEY *pubkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        OSSL_PROVIDER_unload(defprov);
        return -1;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        OSSL_PROVIDER_unload(defprov);
        return -1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, "DHKEM", 0),
        OSSL_PARAM_END
    };

    // Create KEM context for encapsulation
    EVP_PKEY_CTX *kem_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pubkey, "provider=default");
    if (!kem_ctx || EVP_PKEY_encapsulate_init(kem_ctx, params) <= 0) {
        EVP_PKEY_free(pubkey);
        EVP_PKEY_CTX_free(ctx);
        OSSL_PROVIDER_unload(defprov);
        return -1;
    }

    // Perform encapsulation
    size_t ct_len = 65; // Maximum size for P-256
    size_t ss_len = 32; // Shared secret size
    if (EVP_PKEY_encapsulate(kem_ctx, ct, &ct_len, ss, &ss_len) <= 0) {
        EVP_PKEY_CTX_free(kem_ctx);
        EVP_PKEY_free(pubkey);
        EVP_PKEY_CTX_free(ctx);
        OSSL_PROVIDER_unload(defprov);
        return -1;
    }

    EVP_PKEY_CTX_free(kem_ctx);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PROVIDER_unload(defprov);
    return 0;
}

// Decapsulation function
int PQCRYPT_crypto_eckem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) return -1;

    // Create private key from raw bytes
    EVP_PKEY *privkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        OSSL_PROVIDER_unload(defprov);
        return -1;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        OSSL_PROVIDER_unload(defprov);
        return -1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, "DHKEM", 0),
        OSSL_PARAM_END
    };

    // Create KEM context for decapsulation
    EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, privkey, "provider=default");
    if (!dec_ctx || EVP_PKEY_decapsulate_init(dec_ctx, params) <= 0) {
        EVP_PKEY_free(privkey);
        EVP_PKEY_CTX_free(ctx);
        OSSL_PROVIDER_unload(defprov);
        return -1;
    }

    // Perform decapsulation
    size_t ss_len = 32; // Shared secret size
    if (EVP_PKEY_decapsulate(dec_ctx, ss, &ss_len, ct, 65) <= 0) {
        EVP_PKEY_CTX_free(dec_ctx);
        EVP_PKEY_free(privkey);
        EVP_PKEY_CTX_free(ctx);
        OSSL_PROVIDER_unload(defprov);
        return -1;
    }

    EVP_PKEY_CTX_free(dec_ctx);
    EVP_PKEY_free(privkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PROVIDER_unload(defprov);
    return 0;
}