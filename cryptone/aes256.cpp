// 
// https://github.com/oxfemale/Cryptone3/
// twitter: @oxfemale
// email: alice.eas7@gmail.com
// telegram: @BelousovaAlisa
//

#include "stdafx.h"
#include "aes256.h"

/*
AES-256 Encrypt data by 
using openssl lib with given keys:
	unsigned char * key256 = (unsigned char *)"11112222333344445555666677778888"; // обязательно 32 символа (256 бит)
	unsigned char * iv128 = (unsigned char *)"1111333355557777"; // обязательно 16 символов (128 бит)
*/
extern "C" __declspec(dllexport) unsigned char* aes256_encryptC( unsigned char* data, int dataLen, unsigned char * key, unsigned char * iv, int &cryptedlen ) 
{
	int buf_length, out_length;
	const EVP_CIPHER * mode = EVP_aes_256_ctr();
	unsigned char *cipher_text = NULL;

	cipher_text = (unsigned char*)VirtualAlloc( NULL, dataLen, MEM_COMMIT, PAGE_READWRITE );
	if(cipher_text == NULL) return NULL;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (!ctx) { return NULL; }
	if (!EVP_EncryptInit_ex(ctx, mode, NULL, key, iv)) { return NULL; }

	if (!EVP_EncryptUpdate(ctx, cipher_text, &buf_length, data, dataLen)) { return NULL; }
	out_length = buf_length;

	if (!EVP_EncryptFinal_ex(ctx, cipher_text + buf_length, &buf_length)) { return NULL; }
	out_length += buf_length;

	EVP_CIPHER_CTX_free(ctx);
	cryptedlen = out_length;

	return cipher_text;
}

/*
AES-256 Decrypt data by 
using openssl lib with given keys:
	unsigned char * key256 = (unsigned char *)"11112222333344445555666677778888"; // обязательно 32 символа (256 бит)
	unsigned char * iv128 = (unsigned char *)"1111333355557777"; // обязательно 16 символов (128 бит)
*/

extern "C" __declspec(dllexport) unsigned char* aes256_decryptC( unsigned char* cipher, int cipherLen, unsigned char * key, unsigned char * iv, int &decryptLen ) 
{
	int buf_length, out_length;
	const EVP_CIPHER * mode = EVP_aes_256_ctr();
	unsigned char *data_buf = NULL;

	data_buf = (unsigned char*)VirtualAlloc( NULL, cipherLen, MEM_COMMIT, PAGE_READWRITE );
	if(data_buf == NULL) return NULL;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) { return NULL; }
	if (!EVP_DecryptInit_ex(ctx, mode, NULL, key, iv)) { return NULL; }
	if (!EVP_DecryptUpdate(ctx, data_buf, &buf_length, cipher, cipherLen)) { return NULL; }
	out_length = buf_length;
	if (!EVP_DecryptFinal_ex(ctx, data_buf + buf_length, &buf_length)) { return NULL; }
	out_length += buf_length;
	decryptLen = out_length;
	EVP_CIPHER_CTX_free(ctx);

	return data_buf;
}



/*
AES-256 Encrypt data by 
using openssl lib with given keys:
	unsigned char * key256 = (unsigned char *)"11112222333344445555666677778888"; // обязательно 32 символа (256 бит)
	unsigned char * iv128 = (unsigned char *)"1111333355557777"; // обязательно 16 символов (128 бит)
*/
std::string aes256_encrypt(std::string data, unsigned char * key, unsigned char * iv)
{
	int buf_length, out_length;
	const EVP_CIPHER * mode = EVP_aes_256_ctr();
	unsigned char *cipher_text = (unsigned char*)malloc(data.length());
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) { return "ctx is null"; }
	if (!EVP_EncryptInit_ex(ctx, mode, NULL, key, iv)) { return "EVP_EncryptInit_ex error"; }
	if (!EVP_EncryptUpdate(ctx, cipher_text, &buf_length, (unsigned char*)data.c_str(), data.length())) { return "EVP_EncryptUpdate error"; }
	out_length = buf_length;
	if (!EVP_EncryptFinal_ex(ctx, cipher_text + buf_length, &buf_length)) { return "EVP_EncryptFinal_ex error"; }
	out_length += buf_length;
	EVP_CIPHER_CTX_free(ctx);
	std::string out(reinterpret_cast<char*>(cipher_text), out_length);
	free(cipher_text);
	return out;
}

/*
AES-256 Decrypt data by 
using openssl lib with given keys:
	unsigned char * key256 = (unsigned char *)"11112222333344445555666677778888"; // обязательно 32 символа (256 бит)
	unsigned char * iv128 = (unsigned char *)"1111333355557777"; // обязательно 16 символов (128 бит)
*/

std::string aes256_decrypt(std::string cipher, unsigned char * key, unsigned char * iv) 
{
	int buf_length, out_length;
	const EVP_CIPHER * mode = EVP_aes_256_ctr();
	unsigned char *data_buf = (unsigned char*)malloc(cipher.length());
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) { return "ctx is null"; }
	if (!EVP_DecryptInit_ex(ctx, mode, NULL, key, iv)) { return "EVP_DecryptInit_ex error"; }
	if (!EVP_DecryptUpdate(ctx, data_buf, &buf_length, (unsigned char*)cipher.c_str(), cipher.length())) { return "EVP_DecryptUpdate error"; }
	out_length = buf_length;
	if (!EVP_DecryptFinal_ex(ctx, data_buf + buf_length, &buf_length)) { return "EVP_DecryptFinal_ex error"; }
	out_length += buf_length;
	EVP_CIPHER_CTX_free(ctx);
	std::string out(reinterpret_cast<char*>(data_buf), out_length);
	free(data_buf);
	return out;
}

/*
Example:
	unsigned char * key256 = (unsigned char *)"11112222333344445555666677778888"; // обязательно 32 символа (256 бит)
	unsigned char * iv128 = (unsigned char *)"1111333355557777"; // обязательно 16 символов (128 бит)
	std::string data = "Hello World";
	std::string cpp_cipher, php_cipher;
	cpp_cipher = aes256_encrypt(data, EVP_aes_256_ctr(), key256, iv128);
	char* base64 = base64Encode((unsigned char *)cpp_cipher.c_str(), cpp_cipher.length());
	FILE* pFile;
	pFile = fopen("enc.dat", "wb");
	fwrite(base64, 1, strlen(base64),pFile);
	fclose(pFile);
	unsigned char* debase64 = NULL;
	size_t sLen = strlen(base64);
	int iLen = base64Decode(base64, sLen, &debase64);

	std::string cipher = (char*)debase64;
	std::string decrypted = aes256_decrypt(cipher, EVP_aes_256_ctr(), key256, iv128);

	pFile = fopen("dec.dat", "wb");
	fwrite(decrypted.c_str(), 1, decrypted.length(), pFile);
	fclose(pFile);
*/

