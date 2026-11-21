#ifndef MLKEM_WARMUP_H
#define MLKEM_WARMUP_H

#include <stdio.h>
#include "../include/mlkem_keygen.h"
#include "../include/pkey_not_null.h"
#include "../include/get_pubkey_size.h"



int mlkem_warmup (void) {


    size_t pubkey_len;
    EVP_PKEY *client_pkey = mlkem_keygen();

    if (!pkey_is_not_null(client_pkey, "Client ML-KEM-768")) return 1;

    if (!get_pubkey_size(client_pkey, &pubkey_len)) {
        printf("Error getting encoded public key");
        return 1;
    }


    unsigned char *out = NULL, *encaps_secret = NULL;
    size_t outlen = 0, encaps_secretlen = 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_pkey, NULL);
    if (!ctx) {
        printf("ctx points to null\n");
        return 1;
    }

    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) {
        printf("Initialization of encapsulation failed!\n");
        return 1;
    }

    if (EVP_PKEY_encapsulate(ctx, NULL, &outlen, NULL, &encaps_secretlen) <= 0) {
        printf("Error determining the buffer length.\n");
        return 1;
    }

    out = OPENSSL_malloc(outlen);
    encaps_secret = OPENSSL_malloc(encaps_secretlen);
    if (!out || !encaps_secret) {
        printf("output or secret are null, we can't continue unless both are not null.\n");
        return 1;
    }

    if (EVP_PKEY_encapsulate(ctx, out, &outlen, encaps_secret, &encaps_secretlen) <= 0) {
        printf("Encapsulation failed!\n");
        return 1;
    }
  
   

    EVP_PKEY_CTX_free(ctx);


    size_t decaps_secretlen = 0;
    unsigned char *decaps_secret = NULL;


   
    ctx = EVP_PKEY_CTX_new(client_pkey, NULL);
    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
        printf("Error intializing decapsulation.\n");
        return 1;
    }

    /**  Determine buffer length */
    if (EVP_PKEY_decapsulate(ctx, NULL, &decaps_secretlen, out, outlen) <= 0) {
        printf("Error while determining buffer length.\n");
        return 1;
    }

    decaps_secret = OPENSSL_malloc(decaps_secretlen);
    if (!decaps_secret) {
        printf("Error, the decapsulation secret is NULL!\n");
        return 1;
    }

    /**  Decapsulated decaps_secret data is decaps_secretlen bytes long */
    if (EVP_PKEY_decapsulate(ctx, decaps_secret, &decaps_secretlen, out, outlen) <= 0) {
        printf("Error while calculating secret length.\n");
        return 1;
    }
    
  
    /** Verifying that both sides got the same secret */
    int equal = encaps_secretlen == 32 && encaps_secretlen == decaps_secretlen
                && CRYPTO_memcmp(encaps_secret, decaps_secret, encaps_secretlen) == 0;
    
    if (!equal) {
        fprintf(stderr, "secrets differ\n");
        return 1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(client_pkey);
    OPENSSL_clear_free(encaps_secret, encaps_secretlen);
    OPENSSL_clear_free(decaps_secret, decaps_secretlen);
    OPENSSL_free(out);

    return 0;

}
#endif