Data Encryption Standard (DES) algorithm
======

The Data Encryption Standard is a symmetric-key algorithm for the encryption of electronic data.

This project is my implementation of DES standart.

#### Algorithm

![DES Feistel](https://upload.wikimedia.org/wikipedia/commons/thumb/2/25/Data_Encription_Standard_Flow_Diagram.svg/250px-Data_Encription_Standard_Flow_Diagram.svg.png)

[wiki](https://en.wikipedia.org/wiki/Data_Encryption_Standard)

#### Usage
```bash
$ make
$ ./des
Usage:
	<input_file> { -e | -d } <output_file> { -g }
```

Encryption:
```bash
    ./des grummy.jpeg -e enc
```

Decryption:
```bash
    ./des enc -d dec.jpeg
```
