// add.cpp
#include <iostream>
#include <bitset>

using namespace std;
//g++ -shared -o test.so test.cpp
extern "C" {
    long int* add_one(long int** arr, int M, int N) {
        long int* tempArr = (long int*)malloc(N * sizeof(long int)); // allocate memory for the array

        tempArr = arr[0];
        for (int i = 1; i < M; i++) { //500
            for (int j = 0; j < N; j++) { //100000
                tempArr[j] += arr[i][j];
            }
        }

        return tempArr;
    }
}
