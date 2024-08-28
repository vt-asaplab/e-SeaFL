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

#ifndef MY_AES_MODE_CTR_H
# define MY_AES_MODE_CTR_H

extern "C" {
#include "openssl/aes.h"
#include <stdio.h>
}

#define BLOCK_SIZE 16
#define IV_SIZE 16

typedef unsigned int u32;
typedef unsigned char u8;
enum AesKeySize { AES128=128, AES192=192, AES256=256 };

class AesModeCTR
{
private:
    AES_KEY AESkey;
    unsigned char BuffIV[IV_SIZE];
    const unsigned char *piv = BuffIV;

public :
    AesModeCTR(const unsigned char *key, AesKeySize ks, const unsigned char *iv);
    void GetIvCtrMode(size_t c, unsigned char BuffCtr[IV_SIZE]);
    void Encrypt(const unsigned char *in, unsigned char *out, size_t len);
};


#endif
