/*
Copyright 2017 Sathyanesh Krishnan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
Modifications made by Arman, 2024 - Some changes in functionality and structure of the original code.
*/

extern "C" {
#include "openssl/aes.h"
#include <stdio.h>
}

#include "AesModeCTR.h"
#include <chrono>
#include <iostream>

AesModeCTR::AesModeCTR(const unsigned char *key, AesKeySize ks, const unsigned char *iv)
{
    int i = 0;

    i = sizeof(AESkey);
    i = sizeof(AES_KEY);
    for (i = 0; i < IV_SIZE; ++i)
    {
        BuffIV[i] = *(iv + i);
    }    
    AES_set_encrypt_key((const unsigned char *)key, ks, &AESkey);
}

void AesModeCTR::GetIvCtrMode(size_t c, unsigned char IvCtr[IV_SIZE])
{
    const unsigned char *iv = piv;
    size_t *data = (size_t *)IvCtr;
    size_t d = 0;
    size_t n = 0;

    const union
    {
        long one;
        char little;
    } is_endian = {1};

    if (is_endian.little || ((size_t)iv % sizeof(size_t)) != 0)
    {
        n = IV_SIZE;
        do
        {
            --n;
            c += iv[n];
            IvCtr[n] = (u8)c;

            c >>= 8;
        } while (n);
        return;
    }

    n = IV_SIZE / sizeof(size_t);
    do
    {
        --n;
        d = data[n] += c;

        c = ((d - c) ^ d) >> (sizeof(size_t) * 8 - 1);
    } while (n);

    return;
}

void AesModeCTR::Encrypt(const unsigned char *in, unsigned char *out, size_t len)
{
    unsigned char IvCtr[IV_SIZE];
    unsigned char AesCipherOut[BLOCK_SIZE];
    size_t c = 0;
    size_t n = 0;

    while (len >= BLOCK_SIZE)
    {
        GetIvCtrMode(c, IvCtr);
        AES_encrypt(IvCtr, AesCipherOut, (const AES_KEY *)&AESkey);

        for (n = 0; n < BLOCK_SIZE; n += sizeof(size_t))
        {
            *(size_t *)(out + n) = *(size_t *)(in + n) ^ *(size_t *)(AesCipherOut + n);
        }
        len -= BLOCK_SIZE;
        out += BLOCK_SIZE;
        in += BLOCK_SIZE;
        n = 0;
        ++c;
    }

    if (len)
    {
        GetIvCtrMode(c, IvCtr);
        AES_encrypt(IvCtr, AesCipherOut, (const AES_KEY *)&AESkey);
        while (len--)
        {
            out[n] = in[n] ^ AesCipherOut[n];
            ++n;
        }
    }
    
    return;
}
