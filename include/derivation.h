#ifndef DERIVATION_H
#define DERIVATION_H

#include <openssl/evp.h>
#include <stdio.h>


bool derive_shared_secret(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey, unsigned char *secret, size_t *lngth) {
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


#endif