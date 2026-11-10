#ifndef PKEY_NOT_NULL_H
#define PKEY_NOT_NULL_H

#include <openssl/evp.h>
#include <stdio.h>


bool pkey_is_not_null(const EVP_PKEY *pkey, const char *keyname) {
    if (!pkey) {
        printf("pointer '%s' to new key is NULL\n", keyname);
        return false;
    } else {
        return true;
    }
}


#endif