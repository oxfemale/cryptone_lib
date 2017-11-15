// 
// https://github.com/oxfemale/Cryptone3/
// twitter: @oxfemale
// email: alice.eas7@gmail.com
// telegram: @BelousovaAlisa
//

#include "stdafx.h"
#include "openssl/conf.h"
#include "openssl/evp.h"
#include <string>
#include <iostream>

/*
AES-256 Encrypt data by 
using openssl lib with given keys:
	unsigned char * key256 = (unsigned char *)"11112222333344445555666677778888"; // обязательно 32 символа (256 бит)
	unsigned char * iv128 = (unsigned char *)"1111333355557777"; // обязательно 16 символов (128 бит)
return crypted in unsigned char*
*/
extern "C" __declspec(dllexport) unsigned char* aes256_encryptC(unsigned char* data, int dataLen, unsigned char * key, unsigned char * iv, int &cryptedlen);

/*
AES-256 Decrypt data by 
using openssl lib with given keys:
	unsigned char * key256 = (unsigned char *)"11112222333344445555666677778888"; // обязательно 32 символа (256 бит)
	unsigned char * iv128 = (unsigned char *)"1111333355557777"; // обязательно 16 символов (128 бит)
	return decrypted in unsigned char*
*/
extern "C" __declspec(dllexport) unsigned char* aes256_decryptC(unsigned char* cipher, int cipherLen, unsigned char * key, unsigned char * iv, int &decryptLen);

/*
AES-256 Encrypt data by 
using openssl lib with given keys:
	unsigned char * key256 = (unsigned char *)"11112222333344445555666677778888"; // обязательно 32 символа (256 бит)
	unsigned char * iv128 = (unsigned char *)"1111333355557777"; // обязательно 16 символов (128 бит)

*/
std::string aes256_encrypt(std::string data, unsigned char * key, unsigned char * iv);

/*
AES-256 Decrypt data by 
using openssl lib with given keys:
	unsigned char * key256 = (unsigned char *)"11112222333344445555666677778888"; // обязательно 32 символа (256 бит)
	unsigned char * iv128 = (unsigned char *)"1111333355557777"; // обязательно 16 символов (128 бит)
*/
std::string aes256_decrypt(std::string cipher, unsigned char * key, unsigned char * iv);

/*
Example:
	unsigned char * key256 = (unsigned char *)"11112222333344445555666677778888"; // обязательно 32 символа (256 бит)
	unsigned char * iv128 = (unsigned char *)"1111333355557777"; // обязательно 16 символов (128 бит)
	std::string data = "Hello World";
	std::string cpp_cipher, php_cipher;
	cpp_cipher = aes256_encrypt(data, key256, iv128);
	char* base64 = base64Encode((unsigned char *)cpp_cipher.c_str(), cpp_cipher.length());
	FILE* pFile;
	pFile = fopen("enc.dat", "wb");
	fwrite(base64, 1, strlen(base64),pFile);
	fclose(pFile);
	unsigned char* debase64 = NULL;
	size_t sLen = strlen(base64);
	int iLen = base64Decode(base64, sLen, &debase64);

	std::string cipher = (char*)debase64;
	std::string decrypted = aes256_decrypt(cipher, key256, iv128);

	pFile = fopen("dec.dat", "wb");
	fwrite(decrypted.c_str(), 1, decrypted.length(), pFile);
	fclose(pFile);
*/

