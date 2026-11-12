#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <time.h>
#include <stdbool.h>
#include "../include/keygen.h"
#include "../include/pkey_not_null.h"
#include "../include/derivation.h"
#include "../include/get_pubkey_size.h"
#include "../include/get_bn_privkey.h"
#include "../include/privkey_serialization.h"
#include "../include/log_benchmark.h"
#include "../include/warmup.h"
#include "../include/sub_timespec.h"


int main(void) {

    for (int i = 0; i <= 10; i++) warmup();
    /** Generating client and server keys and validating them 
     * before starting to use 'em. Also timing key generation operation,
     * for later logging it into the benchmark
     */
    
    size_t pubkey_len;
    struct timespec start, finish;
    clock_gettime(CLOCK_MONOTONIC, &start);
    EVP_PKEY *client_pkey = gen();
    clock_gettime(CLOCK_MONOTONIC, &finish);
    long long ns = elapsed_ns(start, finish);


    if (!pkey_is_not_null(client_pkey, "client_pkey")) {
        EVP_PKEY_free(client_pkey); 
        return 1;
    }

    if (!get_pubkey_size(client_pkey, &pubkey_len)) {
        printf("Error getting encoded public key");
        return 1;
    }

    if (!log_benchmark(ns, &pubkey_len, ECDH_KEYGEN)) {
        printf("Error logging operation into benchmark\n");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &start);
    EVP_PKEY *server_pkey = gen();
    clock_gettime(CLOCK_MONOTONIC, &finish);
    ns = elapsed_ns(start, finish);

    if (!pkey_is_not_null(server_pkey, "server_pkey"))  {
        EVP_PKEY_free(server_pkey); 
        return 1;
    }

    if (!get_pubkey_size(server_pkey, &pubkey_len)) {
        printf("Error getting encoded public key");
        return 1;
    }

    if (!log_benchmark(ns, &pubkey_len, ECDH_KEYGEN)) {
        printf("Error logging operation into benchmark\n");
        return 1;
    }




    /** Declaring both secrets and a pointer to them len 
      * for later verifying that both sides obtain the same secret */
    unsigned char skey1[32], skey2[32];
    size_t lngth1 = sizeof skey1, lngth2 = sizeof skey2;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_pkey, NULL);
    
    /** Sharing secret via derivation */
    clock_gettime(CLOCK_MONOTONIC, &start);
    if (!derive_shared_secret(ctx, server_pkey, skey1, &lngth1)) return 1;
    clock_gettime(CLOCK_MONOTONIC, &finish);
    ns = elapsed_ns(start, finish);
    
    if (!log_benchmark(ns, &lngth1, ECDH_DERIVATION)) {
        printf("Error logging derivation into benchmark\n");
        return 1;
    }

    ctx = EVP_PKEY_CTX_new(server_pkey, NULL);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (!derive_shared_secret(ctx, client_pkey, skey2, &lngth2)) return 1;
    clock_gettime(CLOCK_MONOTONIC, &finish);
    ns = elapsed_ns(start, finish);
    
    if (!log_benchmark(ns, &lngth2, ECDH_DERIVATION)) {
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

    unsigned char privkey_client_buff[32];
    size_t privkey_client_lngth = sizeof privkey_client_buff;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    if (!privkey_serialization(client_privkey, privkey_client_buff, &privkey_client_lngth)) {
        printf("Error getting the privkey size in bytes");
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &finish);
    ns = elapsed_ns(start, finish);
   
    if (!log_benchmark(ns, &privkey_client_lngth, ECDH_PRIVKEY_SERIALIZATION)) {
        printf("Error logging operation into benchmark\n");
        return 1;
    }
    OPENSSL_cleanse(privkey_client_buff, privkey_client_lngth);


    unsigned char privkey_server_buff[32];
    size_t privkey_server_lngth = sizeof privkey_server_buff;
     
    clock_gettime(CLOCK_MONOTONIC, &start);
    if (!privkey_serialization(server_privkey, privkey_server_buff, &privkey_server_lngth)) {
        printf("Error getting the privkey size in bytes");
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &finish);
    ns = elapsed_ns(start, finish);

    if (!log_benchmark(ns, &privkey_server_lngth, ECDH_PRIVKEY_SERIALIZATION)) {
        printf("Error logging operation into benchmark\n");
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