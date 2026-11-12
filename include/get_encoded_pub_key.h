#ifndef GET_ENCODED_PUB_KEY_H
#define GET_ENCODED_PUB_KEY_H


#include <openssl/evp.h>
#include <stdio.h>


bool get_encoded_pub_key(EVP_PKEY *pkey, size_t *pubkey_len) {
    unsigned char *pubkey;

    *(pubkey_len) = EVP_PKEY_get1_encoded_public_key(pkey, &pubkey);
    if (*(pubkey_len) == 0) return false;


    OPENSSL_free(pubkey);
    return true;
}


#endif