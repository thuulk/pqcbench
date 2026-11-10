#ifndef PRINT_PRIVKEY_H
#define PRINT_PRIVKEY_H

#include <openssl/evp.h>
#include <stdio.h>


static bool print_privkey(BIGNUM *bn_privkey) {
    unsigned char buff[32];
    int lngth = sizeof buff;

    if (BN_bn2binpad(bn_privkey, buff, lngth) < lngth) {
        printf("error when encoding private key\n");
        return false;
    }

    printf("Number of bytes: %i\nEncoded private key: ", lngth);
    for (int i = 0; i < lngth; i++) printf("%02X", buff[i]);
    printf("\n");

    OPENSSL_cleanse(buff, lngth);
    return true;
}


#endif