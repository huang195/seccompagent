#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void print_hex(const char *title, const unsigned char *buf, size_t len) {
    printf("%s: ", title);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

void configure_context(SSL_CTX *ctx) {
    // Set the client certificate and key
    SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM);

    // Load the CA file (to verify the server certificate)
    SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
}

int main(int argc, char **argv) {
    int sock;
    SSL_CTX *ctx;
    SSL_SESSION *session;
    const unsigned char *session_id;
    unsigned int session_id_length;
    unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
    int master_key_length;

    initialize_openssl();
    ctx = create_context();

    configure_context(ctx);

    /* Set up TCP connection to server */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    connect(server_fd, (struct sockaddr*)&addr, sizeof(addr));

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        SSL_write(ssl, "Hello from client", strlen("Hello from client"));
        char buf[1024] = {0};
        SSL_read(ssl, buf, sizeof(buf));
        printf("Received: %s\n", buf);

        // Get the SSL session
        session = SSL_get_session(ssl);

        // Extract the session ID
        session_id = SSL_SESSION_get_id(session, &session_id_length);
        print_hex("Session ID", session_id, session_id_length);

        // Extract the master key (not recommended to use in production)
        master_key_length = SSL_SESSION_get_master_key(session, master_key, sizeof(master_key));
        print_hex("Master Key", master_key, master_key_length);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}

