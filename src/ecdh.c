#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdbool.h>
#include "../include/keygen.h"
#include "../include/pkey_not_null.h"
#include "../include/derivation.h"
#include "../include/get_encoded_pub_key.h"
#include "../include/get_bn_privkey.h"
#include "../include/print_privkey.h"


int main(void) {


    /** Key wrongly configurated to test for handling the exception */
    EVP_PKEY* invalid_pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");

    /** Generating client and server keys and validating them 
     * before starting to use 'em
     */
    EVP_PKEY *client_pkey = gen(), *server_pkey = gen();
    if (!pkey_is_not_null(client_pkey, "client_pkey")) {
        EVP_PKEY_free(client_pkey); 
        return 1;
    }
    if (!pkey_is_not_null(server_pkey, "server_pkey"))  {
        EVP_PKEY_free(server_pkey); 
        return 1;
    }
    if (!pkey_is_not_null(invalid_pkey, "invalid_pkey"))  {
        EVP_PKEY_free(invalid_pkey); 
        return 1;
    }

    /** Declaring both secrets and a pointer to them len 
      * for later verifying that both sides obtain the same secret */
    unsigned char skey1[32], skey2[32], skey3[32];
    size_t lngth1 = sizeof skey1, lngth2 = sizeof skey2, lngth3 = sizeof skey3;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_pkey, NULL);

    /** Handling exception in sharing secret via derivation*/
    if (derive_shared_secret(ctx, invalid_pkey, skey3, &lngth3)) {
        fprintf(stderr, "P-384 peer was accepted when expected rejection\n");
        OPENSSL_cleanse(skey3, lngth3);
        return 1;
    }

    /** ERR_clear_error is for deleting mismatched domain parameters
     * in OPENSSL's error queue. This is done so if later ERR_print_errors_fp
     * is used, it does not show the error on the invalid p-384 peer 
     * secret exchange */
    printf("Invalid P-384 peer rejected (expected)\n");
    ERR_clear_error();

    ctx = EVP_PKEY_CTX_new(client_pkey, NULL);

    /** Sharing secret via derivation */
    if (!derive_shared_secret(ctx, server_pkey, skey1, &lngth1)) return 1;
    ctx = EVP_PKEY_CTX_new(server_pkey, NULL);
    if (!derive_shared_secret(ctx, client_pkey, skey2, &lngth2)) return 1;

    /** Verifying that both sides got the same secret */
    int equal = lngth1 == 32 && lngth1 == lngth2 
                && CRYPTO_memcmp(skey1, skey2, lngth1) == 0;
    printf("len=%zu equal=%d\n", lngth1, equal);
    if (!equal) {
        fprintf(stderr, "secrets differ\n");
        return 1;
    }

    get_encoded_pub_key(client_pkey);
    get_encoded_pub_key(server_pkey);
    
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
    EVP_PKEY_free(invalid_pkey);
    BN_clear_free(client_privkey);
    BN_clear_free(server_privkey);
    OPENSSL_cleanse(skey1, lngth1);
    OPENSSL_cleanse(skey2, lngth2);

    
    printf("success\n");

    return 0;
}