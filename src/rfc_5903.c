#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include "../include/derivation.h"


#define I    "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433"
#define GIX  "DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180"
#define GIY  "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3"
#define GIXY "04" GIX GIY
#define GRX  "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63"
#define GRY  "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB"
#define GIRX "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE"
#define GRXY "04" GRX GRY


/** This file is to test the if the secret is correct for p-256.
 * src/ecdh.c checks if skey1 and skey2 derive the same secrete,
 * but is yet to verify integrity for P-256; thus using the standard RFC 5903
 * 
 * https://www.rfc-editor.org/rfc/rfc5903.html#section-8.1
 * 
 * the program is to generate a key given a known input and know output
 * for validating the correct ECDH P-256 implementation
 */



int main() {

    long bufleninit;
    unsigned char *pubkey = OPENSSL_hexstr2buf(GIXY, &bufleninit);
    BIGNUM *privkey = NULL;
    BN_hex2bn(&privkey, I);

    EVP_PKEY_CTX *ctxinit;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM_BLD *param_bld;
    OSSL_PARAM *params = NULL;

    param_bld = OSSL_PARAM_BLD_new();

    /** This block here tries to create a list of parameters accessing by reference
     * param_bld while constanly checking the return values of the methods used
     * for pushing the parameters (group name, private key, )
     */
    if (privkey != NULL && param_bld != NULL
        && OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                           "prime256v1", 0)
        && OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, privkey)
        && OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                            pubkey, bufleninit))
        params = OSSL_PARAM_BLD_to_param(param_bld);

    ctxinit = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (ctxinit == NULL
        || params == NULL
        || EVP_PKEY_fromdata_init(ctxinit) <= 0
        || EVP_PKEY_fromdata(ctxinit, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
            printf("Error generating pkey from existing parameters");
            return 1;
        }

    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(ctxinit);
    
    
    long buflen_res;
    unsigned char *response_key = OPENSSL_hexstr2buf(GRXY, &buflen_res);
    EVP_PKEY_CTX *ctx_response;
    EVP_PKEY *pkey_response = NULL;
    OSSL_PARAM_BLD *param_bld_response;
    OSSL_PARAM *params_response = NULL;

    param_bld_response = OSSL_PARAM_BLD_new();
    if (param_bld_response != NULL
        && OSSL_PARAM_BLD_push_utf8_string(param_bld_response, OSSL_PKEY_PARAM_GROUP_NAME,
                                           "prime256v1", 0)
        && OSSL_PARAM_BLD_push_octet_string(param_bld_response, OSSL_PKEY_PARAM_PUB_KEY,
                                            response_key, buflen_res))
        params_response = OSSL_PARAM_BLD_to_param(param_bld_response);

    ctx_response = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (ctx_response == NULL
        || params_response == NULL
        || EVP_PKEY_fromdata_init(ctx_response) <= 0
        || EVP_PKEY_fromdata(ctx_response, &pkey_response, EVP_PKEY_PUBLIC_KEY, params_response) <= 0) {
            printf("Error generating pkey from existing parameters");
            return 1;
        }
    
    EVP_PKEY_CTX *final_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    




    unsigned char skey1[32];
    size_t lngth1 = sizeof skey1;
    
    long bufout;
    unsigned char *out = OPENSSL_hexstr2buf(GIRX, &bufout);
    
    if (!out) {
        printf("out is null");
        return 1;
    }

    if (!(bufout == 32)) {
        printf("bufout must be 32");
        return 1;
    }
    if (!derive_shared_secret(final_ctx, pkey_response, skey1, &lngth1)) return 1;
    if (CRYPTO_memcmp(skey1, out, lngth1) != 0) {
        printf("Derivation wrongly handled\n");
        return 1;
    }


    
    printf("Success\n");
    EVP_PKEY_free(pkey);
    OSSL_PARAM_free(params);
    BN_free(privkey);
    OPENSSL_cleanse(skey1, lngth1);
    return 0;
}