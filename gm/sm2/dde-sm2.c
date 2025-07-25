
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "dde-sm2.h"
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

struct _sm2_context {
    EVP_PKEY* key;
    char* private_key;
    char* public_key;
};

// Helper function to print OpenSSL errors
static void print_openssl_errors() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        LOG(LOG_ERR, "OpenSSL error: %s", err_buf);
    }
}

// Implementation of log_print function
void log_print(const char *id, int priority, const char *function, const int line, const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    fprintf(stderr, "[%s:%s:%d] ", id, function, line);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    
    va_end(args);
}

static EVP_PKEY* gen_sm2_key() {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY* pkey = NULL;
    
    // 初始化OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    
    // 使用OpenSSL 3.0的新API生成SM2密钥
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    if (pctx == NULL) {
        LOG(LOG_WARNING, "failed to create SM2 PKEY context.");
        goto end;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        LOG(LOG_WARNING, "failed to init SM2 keygen.");
        goto end;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        LOG(LOG_WARNING, "failed to generate SM2 key pair.");
        print_openssl_errors();
        if (pkey != NULL) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
        goto end;
    }
end:
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    return pkey;
}

static char* get_public_key(EVP_PKEY *key) {
    BIO *bio = NULL;
    unsigned char *pkey = NULL;
    int ret = -1;
    char *publicKey = NULL;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        LOG(LOG_WARNING, "failed to call BIO_new.");
        goto end;
    }

    if (PEM_write_bio_PUBKEY(bio, key) <= 0) {
        LOG(LOG_WARNING, "failed to call PEM_write_bio_PUBKEY.");
        goto end;
    }

    size_t len = BIO_pending(bio);
    if (len == 0) {
        LOG(LOG_WARNING, "failed to get public key length.");
        goto end;
    }
    pkey = (unsigned char *)malloc(len + 1);
    if (pkey == NULL) {
        LOG(LOG_WARNING, "failed to call malloc.");
        goto end;
    }
    if (BIO_read(bio, pkey, len) <= 0) {
        LOG(LOG_WARNING, "failed to call BIO_read.");
        goto end;
    }
    pkey[len] = '\0';

    publicKey = (char*)pkey;
    ret = 0;
end:
    if (bio != NULL) {
        BIO_free(bio);
    }
    if (ret != 0 && pkey != NULL) {
        free(pkey);
    }
    return publicKey;
}

static char* get_private_key(EVP_PKEY *key) {
    BIO *bio = NULL;
    unsigned char *pkey = NULL;
    int ret = -1;
    char *privateKey = NULL;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        LOG(LOG_WARNING, "failed to call BIO_new.");
        goto end;
    }

    ERR_clear_error(); // 清除之前的错误状态
    if (PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) <= 0) {
        print_openssl_errors();
        LOG(LOG_WARNING, "failed to call PEM_write_bio_PrivateKey.");
        goto end;
    }

    size_t len = BIO_pending(bio);
    if (len == 0) {
        LOG(LOG_WARNING, "failed to call BIO_pending.");
        goto end;
    }
    pkey = (unsigned char *)malloc(len + 1);
    if (pkey == NULL) {
        LOG(LOG_WARNING, "failed to call malloc.");
        goto end;
    }
    if (BIO_read(bio, pkey, len) <= 0) {
        LOG(LOG_WARNING, "failed to call BIO_read.");
        goto end;
    }
    pkey[len] = '\0';

    privateKey = (char*)pkey;

    ret = 0;
end:
    if (bio != NULL) {
        BIO_free(bio);
    }
    if (ret != 0 && pkey != NULL) {
        free(pkey);
    }
    return privateKey;
}

int sm2_encrypt(const sm2_context* context, const unsigned char *in, size_t inLen, unsigned char **out, size_t *outLen)
{
    int ret = -1;
    unsigned char *outData = NULL;
    size_t outDataLen = 0;
    EVP_PKEY_CTX *enc_ctx = NULL;
    EVP_PKEY *key = context->key;

    if (in == NULL || key == NULL || out == NULL || outLen == NULL) {
        LOG(LOG_WARNING, "invalid params.");
        goto end;
    }

    // 使用EVP API进行SM2加密
    enc_ctx = EVP_PKEY_CTX_new(key, NULL);
    if (enc_ctx == NULL) {
        LOG(LOG_WARNING, "failed to create encryption context.");
        goto end;
    }

    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) {
        LOG(LOG_WARNING, "SM2 encryption not supported in this OpenSSL version. Error: operation not supported for this keytype");
        print_openssl_errors();
        goto end;
    }

    // 获取密文长度
    if (EVP_PKEY_encrypt(enc_ctx, NULL, &outDataLen, in, inLen) <= 0) {
        LOG(LOG_WARNING, "failed to get ciphertext length.");
        goto end;
    }

    outData = OPENSSL_malloc(outDataLen);
    if (outData == NULL) {
        LOG(LOG_WARNING, "failed to call OPENSSL_malloc.");
        goto end;
    }

    if (EVP_PKEY_encrypt(enc_ctx, outData, &outDataLen, in, inLen) <= 0) {
        LOG(LOG_WARNING, "failed to encrypt data.");
        goto end;
    }

    *out = outData;
    *outLen = outDataLen;
    ret = 0;
end:
    if (enc_ctx != NULL) {
        EVP_PKEY_CTX_free(enc_ctx);
    }
    if (ret != 0 && outData != NULL) {
        OPENSSL_free(outData);
    }
    return ret;
}

int sm2_decrypt(const sm2_context* context, const unsigned char *in, size_t inLen, unsigned char **out, size_t *outLen)
{
    int ret = -1;
    unsigned char *outData = NULL;
    size_t outDataLen = 0;
    EVP_PKEY_CTX *dec_ctx = NULL;
    EVP_PKEY *key = context->key;

    if (in == NULL || key == NULL || out == NULL || outLen == NULL) {
        LOG(LOG_WARNING, "invalid params.");
        goto end;
    }

    // 使用EVP API进行SM2解密
    dec_ctx = EVP_PKEY_CTX_new(key, NULL);
    if (dec_ctx == NULL) {
        LOG(LOG_WARNING, "failed to create decryption context.");
        goto end;
    }

    if (EVP_PKEY_decrypt_init(dec_ctx) <= 0) {
        LOG(LOG_WARNING, "SM2 decryption not supported in this OpenSSL version. Error: operation not supported for this keytype");
        print_openssl_errors();
        goto end;
    }

    // 获取明文长度
    if (EVP_PKEY_decrypt(dec_ctx, NULL, &outDataLen, in, inLen) <= 0) {
        LOG(LOG_WARNING, "failed to get plaintext length.");
        goto end;
    }
    outData = OPENSSL_zalloc(outDataLen+1);
    if (outData == NULL) {
        LOG(LOG_WARNING, "failed to call OPENSSL_malloc.");
        goto end;
    }

    if (EVP_PKEY_decrypt(dec_ctx, outData, &outDataLen, in, inLen) <= 0) {
        LOG(LOG_WARNING, "failed to decrypt data.");
        goto end;
    }

    *out = outData;
    *outLen = outDataLen;
    ret = 0;
end:
    if (dec_ctx != NULL) {
        EVP_PKEY_CTX_free(dec_ctx);
    }
    if (ret != 0 && outData != NULL) {
        OPENSSL_free(outData);
    }
    return ret;
}

sm2_context* new_sm2_context() {
    EVP_PKEY* key = gen_sm2_key();
    if (key == NULL) {
	return NULL;
    }
    sm2_context *ret = malloc(sizeof(sm2_context));
    if (ret == NULL) {
	EVP_PKEY_free(key);
	return NULL;
    }
    ret->key = key;
    ret->private_key = get_private_key(ret->key);
    ret->public_key = get_public_key(ret->key);
    return ret;
}

void free_sm2_context(sm2_context* context) {
    if (context == NULL) {
        return;
    }
    if (context->key) {
	EVP_PKEY_free(context->key);
    }
    if (context->public_key) {
	free(context->public_key);
    }
    if (context->private_key) {
	free(context->private_key);
    }
    free(context);
}
const char* get_sm2_public_key(sm2_context* context) {
    return context->public_key;
}
const char* get_sm2_private_key(sm2_context* context) {
    return context->private_key;
}