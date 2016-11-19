#include <vector>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <ctime>
#include "des.h"

#define BYTE 8

std::vector<unsigned char> readFile(std::ifstream &inputFile) {
	std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(inputFile)), (std::istreambuf_iterator<char>()));
	return buffer;
}

int main(int argc, char* argv[]) {
    srand(time(0));
	if (argc < 3){
		std::cout << "Too few arguments. \n\nUsage:\n\t<input_file> <key_file> { -e | -d } <output_file> { -g }" << std::endl;
		return 0;
	}

	std::ifstream DesFile(argv[1], std::ios::binary);
	if (!DesFile) {
		std::cout << "Error: Unable to open file " << argv[1] << std::endl;
		return 0;
	}

    std::string operation(argv[2]);

    if (operation != "-e" && operation != "-d" && operation != "-g") {
        std::cout << "Error: Wrong operation." << std::endl;
        return 0;
    }

    std::vector<unsigned char> inputDes = readFile(DesFile);

    std::vector<unsigned char> inputKey;
    if(operation == "-e" && argv[4]){
        std::string gen(argv[4]);
        if (gen == "-g") {
            // generate key
            unsigned char alphabet[] = "abcdefghijklmnopqrstuvwxyz1234567890";
            char key[8];
            for(int i = 0; i < 8; ++i) {
                key[i] = alphabet[rand() % 36];
                inputKey.push_back(key[i]);
            }
            key[8] = '\0';
            std::cout << "Your generated key is: " << key << std::endl;
        }
    }
    else {
        // key is only 8 symbols long(!)
        std::cout << "Enter key(just 8 symbols)" << std::endl;
        std::string key;
        getline(std::cin, key);
        std::copy(key.begin(), key.end(), std::back_inserter(inputKey));
    }
    DESCoder des(inputKey);

    std::vector<std::vector <unsigned char> > input;
    std::vector<std::vector <unsigned char> > output;

    while (inputDes.size() % BYTE != 0) {
        inputDes.push_back(0x00);
    }

    for (size_t i = 0, j = 0; i < inputDes.size() / BYTE; i++) {
        std::vector<unsigned char> tmp;
        for (size_t i = 0; i < BYTE; i++) {
            tmp.push_back(inputDes[j]);
            ++j;
        }
        input.push_back(tmp);
    }

    if (operation == "-e") {
        for (size_t i = 0; i < input.size(); i++) {
            output.push_back(des.encode(input[i]));
        }
    }

    if (operation == "-d") {
        for (size_t i = 0; i < input.size(); i++) {
            output.push_back(des.decode(input[i]));
        }
    }

    std::vector<unsigned char> outputDes;

    for (size_t i = 0; i < output.size(); i++) {
        for (size_t j = 0; j < output[i].size(); j++) {
            outputDes.push_back(output[i][j]);
        }
    }

    while (outputDes[outputDes.size() - 1] == 0x00) {
        outputDes.pop_back();
    }

    std::ofstream outputFile(argv[3], std::ios::binary);

    for (size_t i = 0; i < outputDes.size(); i++) {
        outputFile << static_cast<unsigned char>(outputDes[i]);
    }

    outputFile.close();
    std::cout << "Done!" << std::endl;
    return 0;
}
