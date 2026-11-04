#ifndef GET_BN_PRIVKEY_H
#define GET_BN_PRIVKEY_H

#include <openssl/evp.h>
#include <stdio.h>
#include <openssl/core_names.h>


BIGNUM *get_bn_privkey(EVP_PKEY *pkey) {
    BIGNUM *bn_privkey = NULL;
    
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_privkey)) {
        printf("Failed to get the private key in format big number\n");
        return NULL;
    }

    return bn_privkey;
}


#endif