#include <mbedtls/gcm.h>
#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

void sigpipe_handler(int sig);
char *resolve_hostname(const char *hostname);
int recv_all(int sockfd, void *buf, size_t len, int flags);
typedef struct
{
    int from;
    int to;
    pthread_mutex_t *from_mutex;
    pthread_mutex_t *to_mutex;
    int c_or_r;
    char *buf;
} Args;

int aes_256_gcm_encrypt(mbedtls_gcm_context *ctx, const unsigned char *input, size_t input_len,
                        const unsigned char *key, size_t key_len,
                        unsigned char *output, unsigned char *iv, size_t iv_len,
                        unsigned char *tag, size_t tag_len);

int aes_256_gcm_decrypt(mbedtls_gcm_context *ctx, const unsigned char *input, size_t input_len,
                        const unsigned char *key, size_t key_len,
                        unsigned char *output, const unsigned char *iv, size_t iv_len,
                        const unsigned char *tag, size_t tag_len);

int send_socks5(int s, char *hostname, int port);
int tls_handshake(int socks, char *hostname, char *random);