#include <vector>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include "des.h"

#define BYTE 8

DESCoder::DESCoder(std::vector<unsigned char> key) {
    // size of key - 64 bits (8 bytes)
    if (key.size() != BYTE) {
        std::cout << "Error: Wrong key size." << std::endl;
    }

    std::vector<unsigned char> key64 = _bytesArrayToBits(key);

    // generate round keys
    _generateKeys(key64);
}

// encryption and decryption functions are different just in transfer order
std::vector<unsigned char> DESCoder::encode(std::vector<unsigned char> data) {
    return _process(data, true);
}

std::vector<unsigned char> DESCoder::decode(std::vector<unsigned char> data) {
	return _process(data, false);
}

std::vector<unsigned char> DESCoder::_process(std::vector<unsigned char> data, bool encode) {
    // data size for encryption - 64 bits (8 bytes)
    if (data.size() != BYTE) {
        std::cout << "Error: Wrong data size." << std::endl;
    }

    _dataBits = _bytesArrayToBits(data);

    // initial permutation
    _IP();

    // split input data bits to left and right
    _left.clear();
    _left.insert(_left.end(), _dataBits.begin(), _dataBits.begin() + 32);
    _right.clear();
    _right.insert(_right.end(), _dataBits.begin() + 32, _dataBits.end());

    // then we go through 16 rounds
    for (int i = 0; i < 16; ++i) {
        // encryption and decryption keys are different just in transfer order
        if (encode){
            _makeDesStep(_keys[i]);
        }
        else {
            _makeDesStep(_keys[15 - i]);
        }
    }

    std::vector<unsigned char> tmp = _right;
    _right = _left;
    _left = tmp;

    _dataBits.clear();
    _dataBits.insert(_dataBits.end(), _left.begin(), _left.end());
    _dataBits.insert(_dataBits.end(), _right.begin(), _right.end());


    _inverseIP();

    std::vector<unsigned char> result = _bitesArrayToBytes(_dataBits);
    return result;
}

//Initail Permutation (IP)
void DESCoder::_IP() {
    unsigned char ip[] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    std::vector<unsigned char> newDataBits(64);
    for (int i = 0; i < 64; ++i){
        newDataBits[i] = _dataBits[ip[i] - 1];
    }
    this->_dataBits = newDataBits;
    return;
}

void DESCoder::_inverseIP() {
    unsigned char fp[] = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };

    std::vector<unsigned char> newDataBits(64);
    for (int i = 0; i < 64; ++i){
        newDataBits[i] = _dataBits[fp[i] - 1];
    }

    this->_dataBits = newDataBits;
    return;
}

// generation of 48-bit keys for each of the 16 rounds of the algorithm
// input - a 64-bit DES key
// output - 16 48-bit keys for each round of the algorithm
void DESCoder::_generateKeys(std::vector<unsigned char> key64) {
    this->_keys.clear();

    // first 64-bit DES key is reduced to 56 bits
    // discarding each 8th bit

    // array - rule of choosing and mixing 56-bit from 64
    unsigned char pc1[] = {
        57, 49, 41, 33, 25, 17, 9, 1,
        58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7, 62, 54, 46, 38,
        30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4
	};

    std::vector<unsigned char> key56(56);
    for (int i = 0; i < 56; ++i){
        key56[i] = key64[pc1[i] - 1];
    }

    unsigned char leftShifts[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 }; // shift rules

    // rule of generating 48-bit key based on 56-bit
    unsigned char pc2[] = {
        14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32
    };

    for (int j = 0; j < 16; ++j) {
        key56 = _shiftKeyLeft(key56, leftShifts[j]);

        std::vector<unsigned char> iKey(48);
        for (int i = 0; i < 48; ++i) {
            iKey[i] = key56[pc2[i] - 1]; // generate a 48-bit key based on a 56-bit
        }
        this->_keys.push_back(iKey);
    }
}

std::vector<unsigned char> DESCoder::_shiftKeyLeft(std::vector<unsigned char> key56, int numShifts) {
    while (numShifts > 0) {
        unsigned char t1 = key56[0];
        unsigned char t2 = key56[28];

        for (int i = 0; i < 55; ++i) {
            if (i == 27){
                continue;
            }
            key56[i] = key56[i + 1];
        }
        key56[27] = t1;
        key56[55] = t2;
        numShifts--;
    }
    return key56;
}

// one round of DES algorithm
// gist:
// left[i] = right[i - 1]
// right[i] = left[i - 1] ^ F( right[i - 1], key[i] )
void DESCoder::_makeDesStep(std::vector<unsigned char> iKey) {
    std::vector<unsigned char> right48 = _expansion();

    // XOR 48-bit block with 48-bit key
    for (int i = 0; i < 48; ++i){
        right48[i] = right48[i] ^ iKey[i];
    }

    // non linear part of DES algorithm
    std::vector<unsigned char> right32 = _substitution(right48);

    // after the resultant block is subjected to the next permutation
    right32 = _permutation(right32);

    // then XOR with left part
    for (int i = 0; i < 32; ++i){
        right32[i] = right32[i] ^ _left[i];
    }

    // swapping
    _left = _right;
    _right = right32;
}

// expansion right to 48 bits
std::vector<unsigned char> DESCoder::_expansion() {
    unsigned char E[] = {
        32, 1, 2, 3, 4, 5, 4, 5,
        6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27,
        28, 29, 28, 29, 30, 31, 32, 1
    };

    std::vector<unsigned char> expanded(48);
    for (int i = 0; i < 48; ++i){
        expanded[i] = this->_right[E[i] - 1];
    }
    return expanded;
}

std::vector<unsigned char> DESCoder::_substitution(std::vector<unsigned char> right48) {
    unsigned char  sbox[8][4][16] = {
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,	//SBox1

        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,	//SBox2

        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,	//SBox3

        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,	//SBox4

        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,	//SBox5

        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 12, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,	//SBox6

        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,	//SBox7

        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11	//SBox8
    };


    // 48-bit input block is divided by into 8 6-bit sub-blocks
    // (Because only 8 S-boxes for each input receives 6 bits)
    unsigned char a[8][6];
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 6; ++j) {
            a[i][j] = right48[i * 6 + j];
        }
    }

	int g = 0;
	std::vector<unsigned char> res(32);

	for (int i = 0; i < 8; ++i) {
        // Merge bits 1 and 6 - get the number of rows in the table
        int str = a[i][0] * 2 + a[i][5];


        // Merge bits from 2 to 5 - get the column of the table
        int column = 0;
        int pow2 = 8;
        for (int j = 0; j < 4; ++j) {
            column += a[i][j + 1] * pow2;
            pow2 /= 2;
        }

		// get value from S-blocks
		int sValue = sbox[i][str][column];

		// then convert the value to binary form
		int sValueBin[4];
		for (int j = 4; j; j--) {
            sValueBin[j - 1] = sValue % 2;
            sValue /= 2;
		}

        for (int j = 0; j < 4; ++j) {
            res[g++] = sValueBin[j];
        }
    }
	return res;
}

std::vector<unsigned char> DESCoder::_permutation(std::vector<unsigned char> right32) {
    unsigned char per[] = {
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    };

    std::vector<unsigned char> permutated(32);
    for (int i = 0; i < 32; ++i){
        permutated[i] = right32[per[i] - 1];
    }
    return permutated;
}

std::vector<unsigned char> DESCoder::_byteToBits(unsigned char byte) {
    std::vector<unsigned char> res(BYTE);
    int i = 0;
    while (byte > 0) {
        res[i++] = byte % 2;
        byte /= 2;
    }
    return res;
}

std::vector<unsigned char> DESCoder::_bytesArrayToBits(std::vector<unsigned char> bytes) {
    std::vector<unsigned char> result;
    for (unsigned int i = 0; i < bytes.size(); ++i) {
        std::vector<unsigned char> iByteBits = _byteToBits(bytes[i]);

        result.insert(result.end(), iByteBits.begin(), iByteBits.end());
    }
    return result;
}

unsigned char DESCoder::_bitsToByte(std::vector<unsigned char> bits) {
    unsigned char result = 0;
    unsigned char pow2 = 1;
    for (unsigned int i = 0; i < bits.size(); ++i) {
        result += bits[i] * pow2;
        pow2 *= 2;
    }
    return result;
}

std::vector<unsigned char> DESCoder::_bitesArrayToBytes(std::vector<unsigned char> bites) {
    std::vector<unsigned char> res;
    for (unsigned int i = 0; i < bites.size() / BYTE; ++i) {
        std::vector<unsigned char> iBits;
        iBits.insert(iBits.end(), bites.begin() + i * BYTE, bites.begin() + i * BYTE + BYTE);
        unsigned char iByte = _bitsToByte(iBits);
        res.push_back(iByte);
    }
    return res;
}
