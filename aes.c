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
    const unsigned char key[32] = "12312312312312312312312312312312";

    mbedtls_gcm_context ctx;
    char Tag[] = "\xee\x3e\xdf\xf9\xf1\x6a\xc6\x5d\x69"
                 "\xb5\xe8\xdb\x00\x5c\x9e\x1b";
    char data[] = "\x8e\xc5\x7a\x20\x37\xd2\x21\x11\x46"
                  "\x4d\x4b\x69\xc2\x4c\x5b\xab\xf0\x93\x74\x34\xd8\x01\x08\xc6\x48"
                  "\x52\xf7\xfc\xfb\x58\xd6\x27\xb1\x9b\xba\xae\xd7\xd7\x64\x97\x71"
                  "\x90\xf8\xe1\x22\x2d\x36\x64\x8d\xbf\x67\x09\xdc\x83\x17\xab\xc4"
                  "\x6f\x5f\x59\x65\x72\xad\x60\xfe\xa9\x69\x13\x9c\x36\xd6\x0c\x51"
                  "\x30\xf1\xa5\x2c\x73\xeb\x78\x6d";

    mbedtls_gcm_init(&ctx);

    // 加密
    unsigned char iv[12] = {0};
    unsigned char tag[16];
    unsigned char encrypted[sizeof(plaintext)];
    aes_256_gcm_encrypt(&ctx, plaintext, sizeof(plaintext), key, sizeof(key), encrypted, iv, sizeof(iv), tag, sizeof(tag));

    // 解密
    unsigned char decrypted[sizeof(data)];
    int ret = aes_256_gcm_decrypt(&ctx, data, sizeof(data) - 1, key, sizeof(key), decrypted, iv, sizeof(iv), Tag, 16);

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