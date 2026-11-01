# pqcbench

## Objective

Implement and validate **ECDH P-256** (classical) and **ML-KEM-768** (post-quantum) on a
Raspberry Pi 4. Characterize both with a repeatable benchmark methodology, compare execution time
and cryptographic object sizes, and document the classical vs. PQC trade-offs and the
platform-specific limitations.

## TLS handshake

Run all commands from the project root.

1. Generate a 2048-bit RSA private key


   ```sh
   openssl genrsa -out server.key 2048
   ```

2. Create a self-signed certificate valid for 400 days
    ```sh
    openssl req -new -x509 -key server.key -out server.crt \
    -days 400 -subj "/C=US/ST=Test/L=Local/O=DevOrg/OU=Dev/CN=localhost"
    ```

3. Build the client:

   ```sh
   gcc -Wall -g src/main.c -o src/main -lssl -lcrypto
   ```

4. Start the server in terminal 1 and leave it running:

   ```sh
   openssl s_server -accept 4433 -cert server.crt -key server.key -www
   ```

   `-www` makes the server answer the client's HTTP `GET` request with a status page and then
   close the connection. Without it, the client waits forever for a reply.

5. Run the client in terminal 2:

   ```sh
   ./src/main
   ```

   If it works, the client prints the server's `HTTP/1.0 200 ok` page followed by `success`.

> The HTTP `GET` request is temporary. It is only there to confirm that the handshake works
> end to end.
