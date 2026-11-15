#include <stdio.h>
#include "../include/mlkem_keygen.h"
#include "../include/pkey_not_null.h"


int main (void) {


    EVP_PKEY *client_pkey = mlkem_keygen();
    if (!pkey_is_not_null(client_pkey, "Client ML-KEM-768")) return 1;

    EVP_PKEY *server_pkey = mlkem_keygen();
    if (!pkey_is_not_null(server_pkey, "Server ML-KEM-768")) return 1;

    return 0;

}