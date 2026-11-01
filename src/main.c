#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
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
	if (SSL_CTX_use_certificate_file(ctx, "/home/diegor/projects/pqcbench/server.crt",SSL_FILETYPE_PEM) <= 0) {
		printf("Failed to use certificate file\n");
		return 1;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "/home/diegor/projects/pqcbench/server.key", SSL_FILETYPE_PEM) <= 0) {
		printf("Failed to use certificate key\n");
		return 1;
	}

	SSL *ssl = SSL_new(ctx);
	if (!ssl){
		printf("Failed to create the SSL object\n");
		return 1;
	}

	int sock = -1;  //invalid socket
	BIO_ADDRINFO *res;
	const BIO_ADDRINFO *ai = NULL;

	if (!BIO_lookup_ex("www.example.com", "443", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 0, &res)) {
		return 1;
	}

	for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
		sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_STREAM, 0, 0);
		if (sock == -1) continue;
		if (!BIO_connect(sock, BIO_ADDRINFO_address(ai), BIO_SOCK_NODELAY)) {
			BIO_closesocket(sock);
			sock = -1;
			continue;
		}
		break;
	}

	BIO_ADDRINFO_free(res);

	return 0;
}
