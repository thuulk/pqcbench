#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <time.h>
#include <unistd.h>
#include <cjson/cJSON.h>
#include <stdbool.h>
#include "../include/keygen.h"
#include "../include/pkey_not_null.h"
#include "../include/derivation.h"
#include "../include/get_encoded_pub_key.h"
#include "../include/get_bn_privkey.h"
#include "../include/print_privkey.h"
#include "../include/log_benchmark.h"


int main(void) {


    /** Generating client and server keys and validating them 
     * before starting to use 'em. Also timing key generation operation
     */
 
    size_t pubkey_len;
    clock_t start = clock(), diff;
    EVP_PKEY *client_pkey = gen();
    diff = clock() - start;
    double msec = ((double)diff) / CLOCKS_PER_SEC;

    if (!pkey_is_not_null(client_pkey, "client_pkey")) {
        EVP_PKEY_free(client_pkey); 
        return 1;
    }

    if (!get_encoded_pub_key(client_pkey, &pubkey_len)) {
        printf("Error getting encoded public key");
        return 1;
    }

    if (!log_benchmark(msec, &pubkey_len, ECDH_KEYGEN)) {
        printf("Error logging operation into benchmark\n");
        return 1;
    }

    start = clock();
    EVP_PKEY *server_pkey = gen();
    diff = clock() - start;
    msec = ((double)diff) / CLOCKS_PER_SEC;

    if (!pkey_is_not_null(server_pkey, "server_pkey"))  {
        EVP_PKEY_free(server_pkey); 
        return 1;
    }

    if (!get_encoded_pub_key(client_pkey, &pubkey_len)) {
        printf("Error getting encoded public key");
        return 1;
    }

    if (!log_benchmark(msec, &pubkey_len, ECDH_KEYGEN)) {
        printf("Error logging operation into benchmark\n");
        return 1;
    }

    /** Declaring both secrets and a pointer to them len 
      * for later verifying that both sides obtain the same secret */
    unsigned char skey1[32], skey2[32];
    size_t lngth1 = sizeof skey1, lngth2 = sizeof skey2;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_pkey, NULL);
    
    /** Sharing secret via derivation */
    start = clock();
    if (!derive_shared_secret(ctx, server_pkey, skey1, &lngth1)) return 1;
    diff = clock() - start;
    msec = ((double)diff) / CLOCKS_PER_SEC;
    if (!log_benchmark(msec, &lngth1, ECDH_DERIVATION)) {
        printf("Error logging derivation into benchmark\n");
        return 1;
    }

    ctx = EVP_PKEY_CTX_new(server_pkey, NULL);

    start = clock();
    if (!derive_shared_secret(ctx, client_pkey, skey2, &lngth2)) return 1;
    diff = clock() - start;
    msec = ((double)diff) / CLOCKS_PER_SEC;
    if (!log_benchmark(msec, &lngth2, ECDH_DERIVATION)) {
        printf("Error logging derivation into benchmark\n");
        return 1;
    }


    /** Verifying that both sides got the same secret */
    int equal = lngth1 == 32 && lngth1 == lngth2 
                && CRYPTO_memcmp(skey1, skey2, lngth1) == 0;
    printf("len=%zu equal=%d\n", lngth1, equal);
    if (!equal) {
        fprintf(stderr, "secrets differ\n");
        return 1;
    }
    
    //** Generating the private keys as struct BIGNUM */
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

    print_privkey(client_privkey);
    print_privkey(server_privkey);

    EVP_PKEY_free(client_pkey); 
    EVP_PKEY_free(server_pkey);
    BN_clear_free(client_privkey);
    BN_clear_free(server_privkey);
    OPENSSL_cleanse(skey1, lngth1);
    OPENSSL_cleanse(skey2, lngth2);

    
    printf("success\n");

    return 0;
}