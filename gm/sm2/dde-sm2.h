
/*
 * Copyright (C) 2015 ~ 2025 Deepin Technology Co., Ltd.
 *
 * Author:     liaohanqin <liaohanqin@uniontech.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef DDE_SM2_H
#define DDE_SM2_H
#include <stdint.h>
#include <stddef.h>
#include <sys/syslog.h>
#include <stdbool.h>

typedef struct _sm2_context sm2_context;
sm2_context *new_sm2_context();
void free_sm2_context(sm2_context *context);
const char* get_sm2_public_key(sm2_context *context);
const char* get_sm2_private_key(sm2_context *context);
int get_ciphertext_size(const sm2_context *context, size_t plen);
int get_plaintext_size(const uint8_t *ctext, size_t clen);
int sm2_encrypt(const sm2_context *context, const unsigned char *in, size_t inLen, unsigned char **out, size_t *outLen);
int sm2_decrypt(const sm2_context *context, const unsigned char *in, size_t inLen, unsigned char **out, size_t *outLen);

void log_print(const char *id, int priority, const char *function, const int line, const char *format, ...);

#define LOG(priority, text, ...) log_print("dde-sm2", priority, __FUNCTION__, __LINE__, text, ##__VA_ARGS__)

#endif
