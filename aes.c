#include <stdio.h>
#include <string.h>
#include <mbedtls/gcm.h>
#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

int aes_256_gcm_encrypt(mbedtls_gcm_context *ctx, const unsigned char *input, size_t input_len,
                        const unsigned char *key, size_t key_len,
                        unsigned char *output, unsigned char *iv, size_t iv_len,
                        unsigned char *tag, size_t tag_len)
{

    int ret = mbedtls_gcm_setkey(ctx, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
    if (ret != 0)
    {
        return ret;
    }

    ret = mbedtls_gcm_crypt_and_tag(ctx, MBEDTLS_GCM_ENCRYPT, input_len, iv, iv_len, NULL, 0, input, output, tag_len, tag);

    return ret;
}

int aes_256_gcm_decrypt(mbedtls_gcm_context *ctx, const unsigned char *input, size_t input_len,
                        const unsigned char *key, size_t key_len,
                        unsigned char *output, const unsigned char *iv, size_t iv_len,
                        const unsigned char *tag, size_t tag_len)
{

    int ret = mbedtls_gcm_setkey(ctx, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
    if (ret != 0)
    {

        return ret;
    }

    ret = mbedtls_gcm_auth_decrypt(ctx, input_len, iv, iv_len, NULL, 0, tag, tag_len, input, output);

    return ret;
}

int main(void)
{
    // 示例明文和密钥
    const unsigned char plaintext[] = "Hello, World!";
    const unsigned char key[32] = "abcdefghijklmnopqrstuvwxyz123456";

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    // 加密
    unsigned char iv[12];
    unsigned char tag[16];
    unsigned char encrypted[sizeof(plaintext)];
    aes_256_gcm_encrypt(&ctx, plaintext, sizeof(plaintext), key, sizeof(key), encrypted, iv, sizeof(iv), tag, sizeof(tag));

    // 解密
    unsigned char decrypted[sizeof(plaintext)];
    int ret = aes_256_gcm_decrypt(&ctx, encrypted, sizeof(encrypted), key, sizeof(key), decrypted, iv, sizeof(iv), tag, sizeof(tag));

    if (ret == 0)
    {
        printf("Decrypted: %s\n", decrypted);
    }
    else
    {
        printf("Decryption failed\n");
    }

    mbedtls_gcm_free(&ctx);
    return 0;
}