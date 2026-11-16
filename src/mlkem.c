#include <stdio.h>
#include "../include/mlkem_keygen.h"
#include "../include/pkey_not_null.h"


int main (void) {


    EVP_PKEY *client_pkey = mlkem_keygen();
    if (!pkey_is_not_null(client_pkey, "Client ML-KEM-768")) return 1;

    EVP_PKEY *server_pkey = mlkem_keygen();
    if (!pkey_is_not_null(server_pkey, "Server ML-KEM-768")) return 1;


    /** out stands for the output of the later EVP_PKEY_encapsulate method where
     *  the ciphertext is stored
     */
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

    /* Determine buffer length */
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

    /*
    * The generated 'secret' can be used as key material.
    * The encapsulated 'out' can be sent to another party who can
    * decapsulate it using their private key to retrieve the 'secret'.
    */
    if (EVP_PKEY_encapsulate(ctx, out, &outlen, encaps_secret, &encaps_secretlen) <= 0) {
        printf("Encapsulation failed!\n");
        return 1;
    }

    

    return 0;

}