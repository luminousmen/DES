#include <vector>

class DESCoder {
public:
    DESCoder(std::vector<unsigned char> key);

    std::vector<unsigned char> encode(std::vector<unsigned char> data);
    std::vector<unsigned char> decode(std::vector<unsigned char> data);

private:
    std::vector<unsigned char> _process(std::vector<unsigned char> data, bool encode);

    std::vector<unsigned char> _dataBits;
    std::vector<std::vector<unsigned char> > _keys;

    // left part of data
    std::vector<unsigned char> _left;
    // right part of data
    std::vector<unsigned char> _right;

    // initial and final permutation bits
    void _IP();
    void _inverseIP();

    // generate round keys from main key
    void _generateKeys(std::vector<unsigned char> key64);
    std::vector<unsigned char> _shiftKeyLeft(std::vector<unsigned char> key56, int numShifts); // вспомогательная функция для генерации ключей

    // one round of DES algorithm
    // total 16 rounds
    void _makeDesStep(std::vector<unsigned char> iKey);

    // extends _right to 48 bits
    std::vector<unsigned char> _expansion();

    // then extended _right XOR with round key
    // then 48-bit block go throuth S-blocks (substitution)
    // output is - 32-bit block
    std::vector<unsigned char> _substitution(std::vector<unsigned char> right48);

    // then 32-bit block go throuth another permutation - P-block
    std::vector<unsigned char> _permutation(std::vector<unsigned char> right32);

    // then block XOR's with _left part and they swaping
    // then round ends

    // service function array representation byte as array of bits(0 and 1)
    std::vector<unsigned char> _byteToBits(unsigned char byte);

    // service function array representation array of bytes as array of bits(0 and 1)
    std::vector<unsigned char> _bytesArrayToBits(std::vector<unsigned char> bytes);

    // service function array representation bits as a single byte
    unsigned char _bitsToByte(std::vector<unsigned char> bits);

    // service function array representation array of bits as array of bytes
    std::vector<unsigned char> _bitesArrayToBytes(std::vector<unsigned char> bites);
};
