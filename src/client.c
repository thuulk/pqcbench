#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <stdio.h>



int ssl_connection() {
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

	// adding my certificae to my client's trusted list
	if (!SSL_CTX_load_verify_locations(ctx, "/home/diegor/projects/pqcbench/server.crt", NULL)) {
        printf("Failed to load the trusted certificate\n");
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

	if (!BIO_lookup_ex("localhost", "4433", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 0, &res)) {
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


	BIO *bio = BIO_new(BIO_s_socket());  // Create a BIO to wrap the socket
	if (!bio) {
		BIO_closesocket(sock);
		return 1;
	}

	/* 
	 * Associate the newly created BIO with the underlying socket. By
	 * passing BIO_CLOSE here the socket will automatically be closed when
	 * the BIO is freed. Alternatively you can use BIO_NOCLOSE, in which case
	 * one must close the socket explicitly when it's no longer requied.
	 */
	BIO_set_fd(bio, sock, BIO_CLOSE);

	/*
	 * Associating the bio with the SSL object, as I am gonna use the same
	 * BIO for reading and writing direction, we pass BIO twice
	 */
	SSL_set_bio(ssl, bio, bio);

	// Setting server hostname
	if (!SSL_set1_host(ssl, "localhost")) {
		printf("Failed to set the certificate verification hostname\n");
		return 1;
	}

	if (!SSL_set_tlsext_host_name(ssl, "localhost")) {
		printf("Failed to set the SNI hostname\n");
		return 1;
	}

	// Performing the handshake and handling errors from it
	if (SSL_connect(ssl) < 1) {
		printf("Failed to connect to the server\n");
		/*
		 * If the failure is due to a verification error we can get more
		 * information about it from SSL_get_verify_result()
		 */
		if (SSL_get_verify_result(ssl) != X509_V_OK) 
			printf("Verify error: %s\n", 
			X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
		
		return 1;
	}


	size_t written;
	const char *request = "GET / HTTP/1.0\r\nConnection: close\r\nHost: localhost\r\n\r\n";

	// Write an HTTP GET request to the peer
	if (!SSL_write_ex(ssl, request, strlen(request), &written)) {
		printf("Failed to write start of HTTP request\n");
		return 1;
	}

	size_t readbytes;
	char buf[160];
	int ret;


	/**
	 * Get up to sizeof(buf) bytes of the response. We keep reading until the
	 * sever closes the connection
	 */
	while (ret = SSL_read_ex(ssl, buf, sizeof(buf), &readbytes)) {
		
		/**
		 * OpenSSL does not guarantee that the returned data is a tring or
		 * that it is NUL terminated so we use fwrite() to write the exact
		 * number of bytes that we read. The data could be non-printable or 
		 * have NUL characters in the middle of it. For this simple example
		 * we are going to print it to stdout anyway
		 */
		fwrite(buf, 1, readbytes, stdout);
	}
	printf("\n");

	if (SSL_get_error(ssl, ret) != SSL_ERROR_ZERO_RETURN) {	

		/**
		 * Some error occurred other than a graceful shutdown by the 
		 * peer
		 */
		printf("Failed reading remaining data\n");
		return 1;
	}

	ret = SSL_shutdown(ssl);
	if (ret <= 0) {
		/*
		* ret < 0 indicates an error. ret == 0 would be unexpected here
		* because that means "we've sent a close_notify and we're waiting
		* for one back". But we already know we got one from the peer 
		* because of the SSL_ERROR_ZERO_RETURN above.
		*/
		printf("ERROR shutting down\n");
		return 1;
	}

	
	/*
	 * Free the resources we allocated. We do not free the BIO object here
	 * because ownership of it was immediately transferred to the SSL object
	 * via SSL_set_bio(). The BIO will be freed when we free the SSL object
	 */
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	printf("success");

	return 0;
}

int main() {
	ssl_connection();
	return 0;
}
