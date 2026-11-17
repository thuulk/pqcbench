#ifndef ECDH_KEYGEN_H
#define ECDH_KEYGEN_H

#include <openssl/evp.h>

// ECDH p-256 key generation definition
EVP_PKEY *ecdh_keygen(void) { return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); }

#endif