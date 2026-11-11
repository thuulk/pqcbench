#ifndef OPERATION_H
#define OPERATION_H


typedef enum {
    ECDH_KEYGEN,
    ECDH_DERIVATION,
    MLKEM_KEYGEN,
    MLKEM_ENCAPS,
    MLKEM_DECAPS
} operation;


#endif