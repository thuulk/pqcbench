#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

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

static bool derive_shared_secret(EVP_PKEY_CTX *ctx, const EVP_PKEY *pkey, unsigned char secret[32], size_t lngth) {
    if (!ctx) {
        printf("Failed to allocate the public key algorithm\n");
        return false;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        printf("Failed to start deriving shared secret\n");
        return false;
    }

    if (EVP_PKEY_derive_set_peer(ctx, pkey) <= 0){
        printf("Failed to set the peer end\n");
        return false;
    }

    if (EVP_PKEY_derive(ctx, secret, &lngth) <= 0) {
        printf("Failed to accomplish shared derived secret\n");
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

int main(void) {


    /** Generating client and server keys and validating them 
     * before starting to use 'em
     */
    EVP_PKEY *client_pkey = gen(), *server_pkey = gen();
    if (!pkey_is_not_null(client_pkey, "client_pkey")) return 1;
    if (!pkey_is_not_null(server_pkey, "server_pkey")) return 1;

    /** Declaring both secret keys and a pointer to them len 
      * for later verifying that both sides obtain the same secret */
    unsigned char skey1[32], skey2[32];
    size_t lngth1 = sizeof skey1, lngth2 = sizeof skey2;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_pkey, NULL);
    if (!derive_shared_secret(ctx, server_pkey, skey1, lngth1)) return 1;
    
    ctx = EVP_PKEY_CTX_new(server_pkey, NULL);
    if (!derive_shared_secret(ctx, client_pkey, skey2, lngth2)) return 1;

    printf("len=%zu equal=%d\n", lngth1, lngth1 == lngth2 && CRYPTO_memcmp(skey1, skey2, lngth1) == 0);
    EVP_PKEY_free(client_pkey); 
    EVP_PKEY_free(server_pkey);

    
    printf("success\n");

    return 0;
}