#include "../include/mlkem_keygen.h"
#include "../include/pkey_not_null.h"
#include "../include/get_pubkey_size.h"
#include "../include/sub_timespec.h"
#include "../include/log_benchmark.h"
#include "../include/mlkem_warmup.h"


int main (void) {

    for (int i = 0; i < 10; i++) mlkem_warmup();


    size_t pubkey_len;
    struct timespec start, finish;
    clock_gettime(CLOCK_MONOTONIC, &start);
    EVP_PKEY *client_pkey = mlkem_keygen();
    clock_gettime(CLOCK_MONOTONIC, &finish);
    long long ns = elapsed_ns(start, finish);

    if (!pkey_is_not_null(client_pkey, "Client ML-KEM-768")) return 1;

    if (!get_pubkey_size(client_pkey, &pubkey_len)) {
        printf("Error getting encoded public key");
        return 1;
    }

    if (!log_benchmark(ns, &pubkey_len, "MLKEN-768-KEYGEN-REPETITION",
        "ML-KEM-768", "keygen")) {
        printf("Error logging operation into benchmark\n");
        return 1;
    }


    /** ENCAPSULATION OPERATION.
     *  out stands for the output of the later EVP_PKEY_encapsulate method where
     *  the ciphertext is stored
     */
    unsigned char *out = NULL, *encaps_secret = NULL;
    size_t outlen = 0, encaps_secretlen = 0;

    clock_gettime(CLOCK_MONOTONIC, &start);
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
    clock_gettime(CLOCK_MONOTONIC, &finish);
    ns = elapsed_ns(start, finish);
    if (!log_benchmark(ns, &outlen, "MLKEN-768-ENCAPS-REPETITION",
        "ML-KEM-768", "encapsulation")) {
        printf("Error logging operation into benchmark\n");
        return 1;
    }

    EVP_PKEY_CTX_free(ctx);


    size_t decaps_secretlen = 0;
    unsigned char *decaps_secret = NULL;


    clock_gettime(CLOCK_MONOTONIC, &start);
    ctx = EVP_PKEY_CTX_new(client_pkey, NULL);
    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
        printf("Error intializing decapsulation.\n");
        return 1;
    }

    /**  Determine buffer length */
    if (EVP_PKEY_decapsulate(ctx, NULL, &decaps_secretlen, out, outlen) <= 0) {
        printf("Error while determining buffer length.\n");
        return 1;
    }

    decaps_secret = OPENSSL_malloc(decaps_secretlen);
    if (!decaps_secret) {
        printf("Error, the decapsulation secret is NULL!\n");
        return 1;
    }

    /**  Decapsulated decaps_secret data is decaps_secretlen bytes long */
    if (EVP_PKEY_decapsulate(ctx, decaps_secret, &decaps_secretlen, out, outlen) <= 0) {
        printf("Error while calculating secret length.\n");
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &finish);
    ns = elapsed_ns(start, finish);
    if (!log_benchmark(ns, &decaps_secretlen, "MLKEN-768-DECAPS-REPETITION",
        "ML-KEM-768", "decapsulation")) {
        printf("Error logging operation into benchmark\n");
        return 1;
    }
  
    /** Verifying that both sides got the same secret */
    int equal = encaps_secretlen == 32 && encaps_secretlen == decaps_secretlen
                && CRYPTO_memcmp(encaps_secret, decaps_secret, encaps_secretlen) == 0;
    if (!equal) {
        fprintf(stderr, "secrets differ\n");
        return 1;
    }

    unsigned char privkey_buff[2400];
    size_t privkeylen = sizeof privkey_buff;

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (EVP_PKEY_get_raw_private_key(client_pkey, privkey_buff, &privkeylen) <= 0) {
        printf("Error serializing private key.\n");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &finish);
    ns = elapsed_ns(start, finish);

    if (!log_benchmark(ns, &privkeylen, "MLKEN-768-PRIVKEY-SERIALIZATION-REPETITION",
        "ML-KEM-768", "privkey-serialization")) {
        printf("Error logging operation into benchmark\n");
        return 1;
    }


    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(client_pkey);
    OPENSSL_clear_free(encaps_secret, encaps_secretlen);
    OPENSSL_clear_free(decaps_secret, decaps_secretlen);
    OPENSSL_cleanse(privkey_buff, privkeylen);
    OPENSSL_free(out);

    return 0;

}