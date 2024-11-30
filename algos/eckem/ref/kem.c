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

    // Create context with explicit NULL library context
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx)
        return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // Set the curve parameters using the correct parameter name
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}


int PQCRYPT_crypto_eckem_keypair(unsigned char *pk, unsigned char *sk) {
    int ret = -1;
    OSSL_PROVIDER *defprov = NULL;
    EVP_PKEY *keypair = NULL;
    unsigned char *temp_buf = NULL;
    BIGNUM *priv_key_bn = NULL;

    // Load the default provider
    defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) {
        handle_openssl_error();
        goto cleanup;
    }

    // Generate the EC keypair
    keypair = generate_ec_key();
    if (!keypair) {
        handle_openssl_error();
        goto cleanup;
    }

    // Get public key in correct format
    size_t pk_len = 0;
    if (EVP_PKEY_get_octet_string_param(keypair, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pk_len) <= 0) {
        handle_openssl_error();
        goto cleanup;
    }

    if (pk_len > PQCRYPT_CRYPTO_PUBLICKEYBYTES) {
        fprintf(stderr, "Public key too large\n");
        goto cleanup;
    }

    if (EVP_PKEY_get_octet_string_param(keypair, OSSL_PKEY_PARAM_PUB_KEY, pk, PQCRYPT_CRYPTO_PUBLICKEYBYTES, &pk_len) <= 0) {
        handle_openssl_error();
        goto cleanup;
    }

    // Get private key as BIGNUM
    if (EVP_PKEY_get_bn_param(keypair, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key_bn) <= 0 || !priv_key_bn) {
        handle_openssl_error();
        goto cleanup;
    }

    // Convert BIGNUM to fixed-length binary
    if (BN_bn2binpad(priv_key_bn, sk, PQCRYPT_CRYPTO_SECRETKEYBYTES) != PQCRYPT_CRYPTO_SECRETKEYBYTES) {
        fprintf(stderr, "Failed to encode private key\n");
        handle_openssl_error();
        goto cleanup;
    }

    ret = 0; // Success

cleanup:
    if (priv_key_bn) BN_free(priv_key_bn);
    if (keypair) EVP_PKEY_free(keypair);
    if (defprov) OSSL_PROVIDER_unload(defprov);

    return ret;
}

int PQCRYPT_crypto_eckem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov)
        handle_openssl_error();

    int ret = -1;
    EVP_KEM *kem = EVP_KEM_fetch(NULL, "EC", NULL);
    if (!kem) {
        OSSL_PROVIDER_unload(defprov);
        handle_openssl_error();
    }

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key)
        goto cleanup;

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_point = EC_POINT_new(group);
    if (!pub_point)
        goto cleanup;

    size_t pk_len = PQCRYPT_CRYPTO_PUBLICKEYBYTES;

    if (!EC_POINT_oct2point(group, pub_point, pk, pk_len, NULL)) {
        fprintf(stderr, "Failed to decode compressed public key point\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (!EC_KEY_set_public_key(ec_key, pub_point)) {
        fprintf(stderr, "Failed to set public key\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    EC_POINT_free(pub_point);

    EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_COMPRESSED);

    EVP_PKEY *pubkey = EVP_PKEY_new();
    if (!pubkey || !EVP_PKEY_assign_EC_KEY(pubkey, ec_key)) {
        fprintf(stderr, "Failed to create EVP_PKEY\n");
        if (!pubkey) EC_KEY_free(ec_key);
        goto cleanup;
    }
    EVP_PKEY_CTX *kem_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pubkey, "provider=default");
    if (!kem_ctx) {
        fprintf(stderr, "Failed to create KEM context\n");
        goto cleanup;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, "DHKEM", 0),
        OSSL_PARAM_END
    };

    if (EVP_PKEY_encapsulate_init(kem_ctx, params) <= 0) {
        fprintf(stderr, "Failed to initialize encapsulation\n");
        EVP_PKEY_CTX_free(kem_ctx);
        goto cleanup;
    }

    size_t ct_len = PQCRYPT_CRYPTO_CIPHERTEXTBYTES;
    size_t ss_len = PQCRYPT_CRYPTO_BYTES;

    if (EVP_PKEY_encapsulate(kem_ctx, ct, &ct_len, ss, &ss_len) <= 0) {
        fprintf(stderr, "Encapsulation failed\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ret != 0)
        ERR_print_errors_fp(stderr);
    EVP_PKEY_CTX_free(kem_ctx);
    EVP_PKEY_free(pubkey);
    EVP_KEM_free(kem);
    OSSL_PROVIDER_unload(defprov);
    return ret;
}

// Decapsulation function
int PQCRYPT_crypto_eckem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    OSSL_PROVIDER *defprov = NULL;
    EVP_PKEY *privkey = NULL;
    EVP_KEM *kem = NULL;
    EC_KEY *ec_key = NULL;
    EVP_PKEY_CTX *kem_ctx = NULL;
    BIGNUM *priv_bn = NULL;
    int ret = -1;

    // Load provider
    defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) {
        handle_openssl_error();
        goto cleanup;
    }

    // Create EC key structure
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) {
        handle_openssl_error();
        goto cleanup;
    }

    // Convert private key bytes to BIGNUM
    priv_bn = BN_bin2bn(sk, PQCRYPT_CRYPTO_SECRETKEYBYTES, NULL);
    if (!priv_bn) {
        handle_openssl_error();
        goto cleanup;
    }

    // Set private key
    if (!EC_KEY_set_private_key(ec_key, priv_bn)) {
        handle_openssl_error();
        goto cleanup;
    }

    // Get group and generate public key
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_point = EC_POINT_new(group);
    if (!pub_point) {
        handle_openssl_error();
        goto cleanup;
    }

    // Calculate public key point
    if (!EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL)) {
        EC_POINT_free(pub_point);
        handle_openssl_error();
        goto cleanup;
    }

    // Set public key
    if (!EC_KEY_set_public_key(ec_key, pub_point)) {
        EC_POINT_free(pub_point);
        handle_openssl_error();
        goto cleanup;
    }

    EC_POINT_free(pub_point);

    // Convert to EVP_PKEY
    privkey = EVP_PKEY_new();
    if (!privkey || !EVP_PKEY_assign_EC_KEY(privkey, ec_key)) {
        handle_openssl_error();
        if (!privkey) EC_KEY_free(ec_key);
        goto cleanup;
    }

    // Create KEM context
    kem_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, privkey, "provider=default");
    if (!kem_ctx) {
        handle_openssl_error();
        goto cleanup;
    }

    // Initialize decapsulation
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, "DHKEM", 0),
        OSSL_PARAM_END
    };

    if (EVP_PKEY_decapsulate_init(kem_ctx, params) <= 0) {
        handle_openssl_error();
        goto cleanup;
    }

    // Perform decapsulation
    size_t ss_len = PQCRYPT_CRYPTO_BYTES;
    if (EVP_PKEY_decapsulate(kem_ctx, ss, &ss_len, ct, PQCRYPT_CRYPTO_CIPHERTEXTBYTES) <= 0) {
        handle_openssl_error();
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ret != 0) {
        ERR_print_errors_fp(stderr);
    }
    if (kem_ctx) EVP_PKEY_CTX_free(kem_ctx);
    if (privkey) EVP_PKEY_free(privkey);
    if (priv_bn) BN_free(priv_bn);
    if (kem) EVP_KEM_free(kem);
    if (defprov) OSSL_PROVIDER_unload(defprov);
    return ret;
}