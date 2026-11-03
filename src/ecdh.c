#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdbool.h>


#define OSSL_PKEY_PARAM_GROUP_NAME "group"
#define OSSL_PKEY_PARAM_PUB_KEY    "pub"
#define OSSL_PKEY_PARAM_PRIV_KEY   "priv"


// ECDH p-256 key generation definition
static EVP_PKEY *gen(void) { return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); }

static bool pkey_is_not_null(const EVP_PKEY *pkey, const char *keyname) {
    if (!pkey) {
        printf("pointer '%s' to new key is NULL\n", keyname);
        return false;
    } else {
        return true;
    }
}

static bool derive_shared_secret(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey, unsigned char secret[32], size_t *lngth) {
    if (!ctx) {
        printf("Failed to allocate the public key algorithm\n");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        printf("Failed to start deriving shared secret\n");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_derive_set_peer(ctx, pkey) <= 0){
        printf("Failed to set the peer end\n");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_derive(ctx, secret, lngth) <= 0) {
        printf("Failed to accomplish shared derived secret\n");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}


static bool get_encoded_pub_key(EVP_PKEY *pkey) {
    unsigned char *pubkey;
    size_t pubkey_len;

    pubkey_len = EVP_PKEY_get1_encoded_public_key(pkey, &pubkey);
    if (pubkey_len == 0) return false;

    printf("Number of bytes: %zu\nEncoded public key: ", pubkey_len);
    for (size_t i = 0; i < pubkey_len; i++) printf("%02X", pubkey[i]);
    printf("\n");

    OPENSSL_free(pubkey);
    return true;
}


static BIGNUM *get_bn_privkey(EVP_PKEY *pkey, size_t lngth) {
    char curve_name[65];
    unsigned char pub[256];
    BIGNUM *bn_privkey = NULL;

    if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 
                                        sizeof(curve_name), &lngth)) {
        printf("Failed to get utf8 string parameters\n");
        return NULL;
    }

    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, curve_name,
                                         sizeof(curve_name), &lngth)) {
        printf("Failed to get octet string parameters\n");
        return NULL;
    }

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_privkey)) {
        printf("Failed to get the private key in format big number\n");
        return NULL;
    }

    return bn_privkey;
}


static void print_privkey(BIGNUM *bn_privkey) {
    unsigned char buff[32];
    int lngth = sizeof buff;

    if (BN_bn2binpad(bn_privkey, buff, lngth) < lngth) {
        printf("error");
        return;
    }

    printf("Number of bytes: %i\nEncoded private key: ", lngth);
    for (int i = 0; i < lngth; i++) printf("%02X", buff[i]);
    printf("\n");

    
}


int main(void) {


    /** Key wrongly configurated to test for handling the exception */
    EVP_PKEY* invalid_pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");

    /** Generating client and server keys and validating them 
     * before starting to use 'em
     */
    EVP_PKEY *client_pkey = gen(), *server_pkey = gen();
    if (!pkey_is_not_null(client_pkey, "client_pkey")) return 1;
    if (!pkey_is_not_null(server_pkey, "server_pkey")) return 1;

    /** Declaring both secrets and a pointer to them len 
      * for later verifying that both sides obtain the same secret */
    unsigned char skey1[32], skey2[32];
    size_t lngth1 = sizeof skey1, lngth2 = sizeof skey2;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_pkey, NULL);

    /** Handling exception in sharing secret via derivation*/
    if (!derive_shared_secret(ctx, invalid_pkey, skey1, &lngth1)) printf("Wrong config for ECDH p-256\n");
    ctx = EVP_PKEY_CTX_new(client_pkey, NULL);

    /** Sharing secret via derivation */
    if (!derive_shared_secret(ctx, server_pkey, skey1, &lngth1)) return 1;
    ctx = EVP_PKEY_CTX_new(server_pkey, NULL);
    if (!derive_shared_secret(ctx, client_pkey, skey2, &lngth2)) return 1;

    /** Verifying that both sides got the same secret */
    printf("len=%zu equal=%d\n", lngth1, lngth1 == lngth2 && CRYPTO_memcmp(skey1, skey2, lngth1) == 0);

    get_encoded_pub_key(client_pkey);
    get_encoded_pub_key(server_pkey);
    
    BIGNUM *client_privkey = get_bn_privkey(client_pkey, lngth1);
    BIGNUM *server_privkey = get_bn_privkey(server_pkey, lngth2);
    if (!client_privkey) {
        printf("Private key not successfuly gotten\n");
        return 1;
    }

    print_privkey(client_privkey);
    print_privkey(server_privkey);

    EVP_PKEY_free(client_pkey); 
    EVP_PKEY_free(server_pkey);
    EVP_PKEY_free(invalid_pkey);

    
    printf("success\n");

    return 0;
}