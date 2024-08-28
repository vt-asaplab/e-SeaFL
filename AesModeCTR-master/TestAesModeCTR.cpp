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
Modifications made by Arman Riasi, 2024 - Many changes in functionality and structure of the original code.
*/

extern "C" {
#include "openssl/aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
}

#include <chrono>
#include "AesModeCTR.h"
#include <iostream>
using namespace std;

void MyMemSet(unsigned char *p, unsigned int t);
void MyPrintBinData(const unsigned char *BinData, size_t len);

int main()
{
    string input;
    getline(cin, input);

    const char* input_char = input.c_str();
    unsigned char key[44];
    strncpy((char*)key, input_char, 43);
    key[43] = '\0';

    unsigned char BuffEncrypted[1024];
    unsigned char BuffDecrypted[1024];
    size_t len = 0;

    MyMemSet(BuffEncrypted, sizeof(BuffEncrypted));
    MyMemSet(BuffDecrypted, sizeof(BuffDecrypted));

    unsigned char *OriginalData = (unsigned char *)"1370000000000000";

    len = strlen((const char *)OriginalData);

    long long iv_int = 11111007890123456;
    unsigned char iv[16];
    long long durationList[4000];
    long long totalDuration = 0;

    for (int i = 0; i < 4000; ++i) {
        iv_int += 10;
        sprintf(reinterpret_cast<char*>(iv), "%ld", iv_int);

        AesModeCTR aesctr(key, AesKeySize::AES256, iv);
        
        auto start = std::chrono::high_resolution_clock::now();
        aesctr.Encrypt(OriginalData, BuffEncrypted, len);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        durationList[i] = duration.count();

        MyPrintBinData(BuffEncrypted, len);
    }
    for(int i = 1; i < 4000; i++)
        totalDuration += durationList[i];
    std::cout << totalDuration << " nanoseconds" << std::endl;

    return(0);
}

void MyMemSet(unsigned char *p, unsigned int t)
{
    unsigned int i = 0;
    for (i = 0; i < t; ++i)
    {
        *p++ = 0;
    }
}

void MyPrintBinData(const unsigned char *BinData, size_t len)
{
    size_t i;
    int DisplayBlockSeparation = 0;

    for (i = 0; i < len; i++)
    {
        printf("%X", BinData[i] / 16);
        printf("%X", BinData[i] % 16);

        ++DisplayBlockSeparation;
        if (DisplayBlockSeparation == 4)
        {
            DisplayBlockSeparation = 0;
            printf(" ");
        }
    }
    printf("\n");
}
