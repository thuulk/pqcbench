#ifndef ECDH_PRIVKEY_SERIALIZATION_H
#define ECDH_PRIVKEY_SERIALIZATION_H

#include <openssl/evp.h>
#include <stdio.h>


bool ecdh_privkey_serialization(BIGNUM *bn_privkey, unsigned char *buff, size_t *lngth) {

    if (BN_bn2binpad(bn_privkey, buff, *lngth) < *lngth) return false;
    return true;

}


#endif