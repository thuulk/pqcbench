#ifndef ECDH_WARMUP_H
#define ECDH_WARMUP_H


#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdbool.h>
#include "../include/ecdh_keygen.h"
#include "../include/pkey_not_null.h"
#include "../include/derivation.h"
#include "../include/get_pubkey_size.h"
#include "../include/get_bn_privkey.h"
#include "../include/ecdh_privkey_serialization.h"



int ecdh_warmup () {

    size_t pubkey_len;
    EVP_PKEY *client_pkey = ecdh_keygen();
    

    if (!pkey_is_not_null(client_pkey, "client_pkey")) {
        EVP_PKEY_free(client_pkey); 
        return 1;
    }

    if (!get_pubkey_size(client_pkey, &pubkey_len)) {
        printf("Error getting encoded public key");
        return 1;
    }

    EVP_PKEY *server_pkey = ecdh_keygen();
    

    if (!pkey_is_not_null(server_pkey, "server_pkey"))  {
        EVP_PKEY_free(server_pkey); 
        return 1;
    }

    if (!get_pubkey_size(server_pkey, &pubkey_len)) {
        printf("Error getting encoded public key");
        return 1;
    }


    unsigned char skey1[32], skey2[32];
    size_t lngth1 = sizeof skey1, lngth2 = sizeof skey2;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_pkey, NULL);
    
    
    if (!derive_shared_secret(ctx, server_pkey, skey1, &lngth1)) return 1;

    ctx = EVP_PKEY_CTX_new(server_pkey, NULL);


    if (!derive_shared_secret(ctx, client_pkey, skey2, &lngth2)) return 1;
    
    BIGNUM *client_privkey = get_bn_privkey(client_pkey);
    BIGNUM *server_privkey = get_bn_privkey(server_pkey);
    if (!client_privkey) {
        printf("Private key not successfuly gotten\n");
        return 1;
    }

    if (!server_privkey) {
        printf("Private key not successfuly gotten\n");
        return 1;
    }

    unsigned char privkey_client_buff[32];
    size_t privkey_client_lngth = sizeof privkey_client_buff;
    if (!ecdh_privkey_serialization(client_privkey, privkey_client_buff, &privkey_client_lngth)) {
        printf("Error getting the privkey size in bytes");
        return 1;
    }
    
    OPENSSL_cleanse(privkey_client_buff, privkey_client_lngth);

    unsigned char privkey_server_buff[32];
    size_t privkey_server_lngth = sizeof privkey_server_buff;
    if (!ecdh_privkey_serialization(server_privkey, privkey_server_buff, &privkey_server_lngth)) {
        printf("Error getting the privkey size in bytes");
        return 1;
    }


    EVP_PKEY_free(client_pkey); 
    EVP_PKEY_free(server_pkey);
    BN_clear_free(client_privkey);
    BN_clear_free(server_privkey);
    OPENSSL_cleanse(skey1, lngth1);
    OPENSSL_cleanse(skey2, lngth2);

    return 0;
}


#endif