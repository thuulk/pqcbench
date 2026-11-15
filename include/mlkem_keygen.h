#ifndef MLKEM_KEYGEN_H
#define MLKEM_KEYGEN_H

#include <openssl/evp.h>

// ML-KEM-768 key generation definition
EVP_PKEY *mlkem_keygen(void) { return EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768"); }

#endif