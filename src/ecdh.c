#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// ECDH p-256 key generation definition
static EVP_PKEY *gen(void) { return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); }

int main(void) {


    // generating client and server public keys
    EVP_PKEY *client_pkey = gen(), *server_pkey = gen();

    //** Invalid key for testing maluse of inputs on derived shared secret */
    EVP_PKEY *invalid_Pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");

    if (!client_pkey && server_pkey) {
        printf("pointer 'client_pkey' to new key is NULL\n");
        return 1;
    }

    if (client_pkey && !server_pkey) {
        printf("pointer 'server_pkey' to new key is NULL\n");
        return 1;
    }

    if (!client_pkey && !server_pkey) {
        printf("both pointers to new key are NULL\n");
        return 1;
    }

    unsigned char s1[32], s2[32];
    size_t l1 = sizeof s1, l2 = sizeof s2;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_pkey, NULL);

    if (!ctx) {
        printf("Failed to allocate the public key algorithm\n");
        return 1;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        printf("Failed to start deriving shared secret\n");
        return 1;
    }
    
    if (EVP_PKEY_derive_set_peer(ctx, invalid_Pkey) <= 0){
        printf("Invalid peer rejected\n");
        ERR_print_errors_fp(stdout);
        return 1;
    }

    if (EVP_PKEY_derive_set_peer(ctx, server_pkey) <= 0){
        printf("Failed to set the peer end\n");
        return 1;
    }

    if (EVP_PKEY_derive(ctx, s1, &l1) <= 0) {
        printf("Failed to accomplish shared derived secret\n");
        return 1;
    }
    EVP_PKEY_CTX_free(ctx);

    ctx = EVP_PKEY_CTX_new(server_pkey, NULL);
    
    if (!ctx) {
        printf("Failed to allocate the public key algorithm\n");
        return 1;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        printf("Failed to start deriving shared secret\n");
        return 1;
    }

    if (EVP_PKEY_derive_set_peer(ctx, client_pkey) <= 0) {
        printf("Failed to set the peer end\n");
        return 1;
    }

    if (EVP_PKEY_derive(ctx, s2, &l2) <= 0) {
        printf("Failed to accomplish shared derived secret\n");
        return 1;
    }

    EVP_PKEY_CTX_free(ctx);

    printf("len=%zu equal=%d\n", l1, l1 == l2 && CRYPTO_memcmp(s1, s2, l1) == 0);
    EVP_PKEY_free(client_pkey); 
    EVP_PKEY_free(server_pkey);

    
    printf("success\n");

    return 0;
}