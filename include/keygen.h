#ifndef KEYGEN_H
#define KEYGEN_H

#include <openssl/evp.h>

// ECDH p-256 key generation definition
EVP_PKEY *gen(void) { return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); }

#endif