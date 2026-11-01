#include <stdio.h>
#include <openssl/evp.h>

static EVP_PKEY *gen(void) { return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); }

int derive(void) {
    EVP_PKEY *a = gen(), *b = gen();
    unsigned char s1[32], s2[32];
    size_t l1 = sizeof s1, l2 = sizeof s2;

    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(a, NULL);
    EVP_PKEY_derive_init(c);
    EVP_PKEY_derive_set_peer(c, b);
    EVP_PKEY_derive(c, s1, &l1);
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new(b, NULL);
    EVP_PKEY_derive_init(c);
    EVP_PKEY_derive_set_peer(c, a);
    EVP_PKEY_derive(c, s2, &l2);
    EVP_PKEY_CTX_free(c);

    printf("len=%zu equal=%d\n", l1, l1 == l2 && CRYPTO_memcmp(s1, s2, l1) == 0);
    EVP_PKEY_free(a); EVP_PKEY_free(b);
    return 0;

}

int main(void) {
    return derive();
}