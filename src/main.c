#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

int main() {
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {
		printf("Failed to create the SSX_CTX\n");
		return 1;
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	
	if (!SSL_CTX_set_default_verify_paths(ctx)) {
		printf("Failed to set the default trusted certificate store\n");
		return 1;
	}

	if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
		printf("Failed to set the minimum TLS protocol\n");
		return 1;
	}
	if (SSL_CTX_use_certificate_file(ctx, "server.crt",SSL_FILETYPE_PEM) <= 0) {
		printf("Failed to use certificate file\n");
		return 1;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
		printf("Failed to use certificate key\n");
		return 1;
	}

	SSL *ssl = SSL_new(ctx);
	if (!ssl){
		printf("Failed to create the SSL object\n");
		return 1;
	}


	return 0;
}
