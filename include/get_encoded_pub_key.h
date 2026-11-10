#ifndef GET_ENCODED_PUB_KEY_H
#define GET_ENCODED_PUB_KEY_H


#include <openssl/evp.h>
#include <stdio.h>


bool get_encoded_pub_key(EVP_PKEY *pkey) {
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


#endif