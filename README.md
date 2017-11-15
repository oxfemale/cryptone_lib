# Cryptone
MSVC++ DLL/LIB project - A cryptographic library for exchanging traffic with a web server<br>
Used lib/dll OpenSSL 1.1.0 and Zlib 1.2.7

crypton.dll use:<br>
Functions: AES-256 Encrypt/Decrypt binary message/binary data (any size)<br>
Functions  RSA-2048/sha256 Generate Private/Public/Certificate to memory or to files<br>
Functions: RSA-2048/sha256 Crypt/Decrypt message  (max 240 byte message)<br>
Functions: RSA-2048/sha256 Crypt/Decrypt any binary file size to output file<br>
Functions: Zlib stream deflate(zip)/inflate(unzip) message/binary data<br>
Functions: Convert char*->HexChar*/HexChar*->char*, example "123"->"313233", "313233"->"123"<br>
Functions: char*->base64, base64->char*<br>
<br>
```cpp
/*
AES-256 Encrypt data by 
using openssl lib with given keys:
	unsigned char * key256 = (unsigned char *)"11112222333344445555666677778888"; // îáÿçàòåëüíî 32 ñèìâîëà (256 áèò)
	unsigned char * iv128 = (unsigned char *)"1111333355557777"; // îáÿçàòåëüíî 16 ñèìâîëîâ (128 áèò)
return crypted in unsigned char*
*/
unsigned char* aes256_encryptC(unsigned char* data, int dataLen, unsigned char * key, unsigned char * iv, int &cryptedlen);
```

```cpp
/*
AES-256 Decrypt data by 
using openssl lib with given keys:
	unsigned char * key256 = (unsigned char *)"11112222333344445555666677778888"; // îáÿçàòåëüíî 32 ñèìâîëà (256 áèò)
	unsigned char * iv128 = (unsigned char *)"1111333355557777"; // îáÿçàòåëüíî 16 ñèìâîëîâ (128 áèò)
	return decrypted in unsigned char*
*/
unsigned char* aes256_decryptC(unsigned char* cipher, int cipherLen, unsigned char * key, unsigned char * iv, int &decryptLen);
```	


```cpp
//Generate new RSA-2048/sha256 keys Private/Public/Certificate and save it to files
//Set IfFilesExistsNotRewriteset to false for overwrite files
//if Error return false
bool GenRSAKeysPhp( char* privateFile, char* publicFile, char* CertificateFile, bool IfFilesExistsNotRewrite );
```	

```cpp
//Generate new RSA-2048/sha256 RSA key Private/Public/Certificate and save it memory
//if Error return false
bool GenRSAKeysToMem( unsigned char** PrivateKeyStr, unsigned char** PublicKeyStr, unsigned char** CertificateKeyStr );
```	


```cpp
//Ecrypt data by RSA-2048/sha256 Public key
// unsigned char *encrypted - must be allocated before call public_encrypt()
// return encrypted size or -1 if error
int public_encrypt( unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted );
```	

```cpp
//Decrypt data by RSA-2048/sha256 Private key
// unsigned char *decrypted - must be allocated before call private_decrypt()
// return encrypted size or -1 if error
int private_decrypt( unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted );
```	

```cpp
//Encrypt data by RSA-2048/sha256 Private Key
// unsigned char *encrypted - must be allocated before call private_encrypt()
// return encrypted size or -1 if error
int private_encrypt( unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted );
```	

```cpp
//Dencrypt data by RSA-2048/sha256 Public Key
// unsigned char *decrypted - must be allocated before call public_decrypt()
// return encrypted size or -1 if error
int public_decrypt( unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted );
```	


```cpp
//Encrypt any size InFile with RSA-2048/sha256 Private key and put it in the OutFile 
//On error return 0, if ok return 1
DWORD CryptFilePrivate256( char* FileName, char* NewFileName, unsigned char *privateKey );
```	

```cpp
//Encrypt any size InFile with RSA-2048/sha256 Public key and put it in the OutFile 
//On error return 0, if ok return 1
DWORD CryptFilePublic256( char* FileName, char* NewFileName, unsigned char *publicKey )
```	

```cpp
//Dencrypt any size InFile with RSA-2048/sha256 Private key and put it in the OutFile 
//On error return 0, if ok return 1
DWORD DeCryptFilePrivate256( char* FileName, char* NewFileName, unsigned char *privateKey );
```	

```cpp
//Dencrypt any size InFile with RSA-2048/sha256 Public key and put it in the OutFile 
//On error return 0, if ok return 1
DWORD DeCryptFilePublic256( char* FileName, char* NewFileName, unsigned char *publicKey );
```	


```cpp
//Compress char*, gzip style using zlib with given compression level
//return compressed data with size in "unzippedLen" or NULL if error
char* compress_stringC( char* strData, int strDataLen, int &zippedLen );
```	

```cpp
//Decompress char* data by len
//return decompressed data with size in "unzippedLen" or NULL if error
char* decompress_stringC( char* strData, int strDataLen, int &unzippedLen );
```	


```cpp
//Convert char* hex hex format->char*, for example "313233" in hex -> "123"
//return char* text or NULL if error
char* charHex2char( unsigned char* data, int dataLen );
```	

```cpp
//Convert char* -> char* in hex format, for example "123" -> "313233" in hex
//return char* text or NULL if error
char* char2charHex ( unsigned char* zip, int size );
```	


```cpp
//Encode base64 for char* and return new char*
//return base64 string or NULL if error
char* base64Encode( const unsigned char *message, const size_t length );
```	

```cpp
//Decode base64 for char* and return new char*
//return decoded data size and data in "buffer", On Error return NULL in "buffer"
int base64Decode( const char *b64message, const size_t length, unsigned char **buffer );
```	


 Example use:


```cpp
#include "stdafx.h"
#include <stdio.h>	
#include <windows.h>
#include <math.h>
#include <iostream>
#include <vector>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <ctime>
#include <string>
#include <iostream>
#include <algorithm>
#include <stdexcept>

typedef unsigned char* ( *aes256_encryptCExp )(  unsigned char* data, int dataLen, unsigned char * key, unsigned char * iv, int &cryptedlen );
typedef unsigned char* ( *aes256_decryptCExp )( unsigned char* cipher, int cipherLen, unsigned char * key, unsigned char * iv, int &decryptLen );
typedef char* ( *base64EncodeExp )( const unsigned char *message, const size_t length );
typedef int   ( *base64DecodeExp )( const char *b64message, const size_t length, unsigned char **buffer );
typedef char* ( *charHex2charExp )( unsigned char* data, int dataLen );
typedef char* ( *char2charHexExp )( unsigned char* data, int dataLen );
typedef char* ( *compress_stringCExp )( char* strData, int strDataLen, int &zippedLen );
typedef char* ( *decompress_stringCExp )( char* strData, int strDataLen, int &unzippedLen );
typedef bool ( *GenRSAKeysPhpExp )( char* privateFile, char* publicFile, char* CertificateFile, bool IfFilesExistsNotRewrite );
typedef bool ( *GenRSAKeysToMemExp )( unsigned char** PrivateKeyStr, unsigned char** PublicKeyStr, unsigned char** CertificateKeyStr );
typedef int ( *public_encryptExp )( unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted );
typedef int ( *private_decryptExp )( unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted );
typedef int ( *private_encryptExp )( unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted );
typedef int ( *public_decryptExp )(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted );
typedef DWORD ( *CryptFilePrivate256Exp )( char* FileName, char* NewFileName, unsigned char *privateKey );
typedef DWORD ( *DeCryptFilePrivate256Exp )( char* FileName, char* NewFileName, unsigned char *privateKey );
typedef DWORD ( *CryptFilePublic256Exp )( char* FileName, char* NewFileName, unsigned char *publicKey );
typedef DWORD ( *DeCryptFilePublic256Exp )( char* FileName, char* NewFileName, unsigned char *publicKey );


int _tmain(int argc, _TCHAR* argv[])
{
	aes256_encryptCExp aes256_encryptC = 0;
	aes256_decryptCExp aes256_decryptC = 0;
	base64EncodeExp base64Encode = 0;
	base64DecodeExp base64Decode = 0;
	charHex2charExp charHex2char = 0;
	char2charHexExp char2charHex = 0;
	compress_stringCExp compress_stringC = 0;
	decompress_stringCExp decompress_stringC = 0;
	GenRSAKeysPhpExp GenRSAKeysPhp = 0;
	GenRSAKeysToMemExp GenRSAKeysToMem = 0;
	public_encryptExp public_encrypt = 0;
	private_decryptExp private_decrypt = 0;
	private_encryptExp private_encrypt = 0;
	public_decryptExp public_decrypt = 0;

	CryptFilePrivate256Exp CryptFilePrivate256 = 0;
	DeCryptFilePrivate256Exp DeCryptFilePrivate256 = 0;
	CryptFilePublic256Exp CryptFilePublic256 = 0;
	DeCryptFilePublic256Exp DeCryptFilePublic256 = 0;

	char* cryptone = "cryptone.dll";
	HMODULE hModule = LoadLibraryA(cryptone);
	if(hModule == NULL) 
	{
		printf("Error[%d] load [%s] dll\r\n", GetLastError(), cryptone);
		return 0;
	}

	aes256_encryptC = (aes256_encryptCExp)GetProcAddress(hModule, "aes256_encryptC");
	if(aes256_encryptC == NULL) return 0;
	aes256_decryptC = (aes256_decryptCExp)GetProcAddress(hModule, "aes256_decryptC");
	if(aes256_decryptC == NULL) return 0;
	base64Encode = (base64EncodeExp)GetProcAddress(hModule, "base64Encode");
	if(base64Encode == NULL) return 0;
	base64Decode = (base64DecodeExp)GetProcAddress(hModule, "base64Decode");
	if(base64Decode == NULL) return 0;
	charHex2char = (charHex2charExp)GetProcAddress(hModule, "charHex2char");
	if(charHex2char == NULL) return 0;
	char2charHex = (char2charHexExp)GetProcAddress(hModule, "char2charHex");
	if(char2charHex == NULL) return 0;
	compress_stringC = (compress_stringCExp)GetProcAddress(hModule, "compress_stringC");
	if(compress_stringC == NULL) return 0;
	decompress_stringC = (decompress_stringCExp)GetProcAddress(hModule, "decompress_stringC");
	if(decompress_stringC == NULL) return 0;
	GenRSAKeysPhp = (GenRSAKeysPhpExp)GetProcAddress(hModule, "GenRSAKeysPhp");
	if(GenRSAKeysPhp == NULL) return 0;
	GenRSAKeysToMem = (GenRSAKeysToMemExp)GetProcAddress(hModule, "GenRSAKeysToMem");
	if(GenRSAKeysToMem == NULL) return 0;
	public_encrypt = (public_encryptExp)GetProcAddress(hModule, "public_encrypt");
	if(public_encrypt == NULL) return 0;
	private_decrypt = (private_decryptExp)GetProcAddress(hModule, "private_decrypt");
	if(private_decrypt == NULL) return 0;
	private_encrypt = (private_encryptExp)GetProcAddress(hModule, "private_encrypt");
	if(private_encrypt == NULL) return 0;
	public_decrypt = (public_decryptExp)GetProcAddress(hModule, "public_decrypt");
	if(public_decrypt == NULL) return 0;

	CryptFilePrivate256 = (CryptFilePrivate256Exp)GetProcAddress(hModule, "CryptFilePrivate256");
	if(CryptFilePrivate256 == NULL) return 0;
	DeCryptFilePrivate256 = (DeCryptFilePrivate256Exp)GetProcAddress(hModule, "DeCryptFilePrivate256");
	if(DeCryptFilePrivate256 == NULL) return 0;
	CryptFilePublic256 = (CryptFilePublic256Exp)GetProcAddress(hModule, "CryptFilePublic256");
	if(CryptFilePublic256 == NULL) return 0;
	DeCryptFilePublic256 = (DeCryptFilePublic256Exp)GetProcAddress(hModule, "DeCryptFilePublic256");
	if(DeCryptFilePublic256 == NULL) return 0;

	//Generate RSA keys and save it to files example
	char* PriName = "Private.pem";
	char* PubName = "Public.pem";
	char* CerName = "Certif.pem";
	bool bFlag = false; // if set true - overwrite and generate new public/private keys
    if(GenRSAKeysPhp(PriName, PubName, CerName, bFlag) == false ) return 0;
	
	//Generate RSA keys and save it to memory example
	unsigned char* PrivateKeyStr = NULL;
	unsigned char* PublicKeyStr = NULL;
	unsigned char* CertificateKeyStr = NULL;
    if(GenRSAKeysToMem( &PrivateKeyStr, &PublicKeyStr, &CertificateKeyStr ) == false ) return 0;
	VirtualFree( PrivateKeyStr, 0, MEM_RELEASE );
	VirtualFree( PublicKeyStr, 0, MEM_RELEASE );
	VirtualFree( CertificateKeyStr, 0, MEM_RELEASE );


	//Generate new RSA keys and Encrypt UserFile(any size) with privateKey -> Decrypt UserFile with publicKey and save it to file example
	unsigned char* PrivateKeyStr111 = NULL;
	unsigned char* PublicKeyStr111 = NULL;
	unsigned char* CertificateKeyStr111 = NULL;
	if(GenRSAKeysToMem( &PrivateKeyStr111, &PublicKeyStr111, &CertificateKeyStr111 ) == false ) return 0;
	int fileSize1 = 20548;
	char fileData1[20548];
	memset(fileData1, 'A', fileSize1 );
	char* inFileName1 = "inFile1.txt";
	char* outFileName1 = "outFile1.txt";
	char* outFileName21 = "outFile21.txt";
	FILE* pFile11 = fopen( inFileName1, "wb" );
	fwrite( fileData1, 1, fileSize1, pFile11 );
	if ( ferror( pFile11 ) )
	{
		fclose( pFile11 );
		VirtualFree( PrivateKeyStr111, 0, MEM_RELEASE );
		VirtualFree( PublicKeyStr111, 0, MEM_RELEASE );
		VirtualFree( CertificateKeyStr111, 0, MEM_RELEASE );
		return 0;
	}
	fclose( pFile11 );
	if( CryptFilePublic256( inFileName1, outFileName1, PublicKeyStr111 ) == 0 ) return 0;
	if( DeCryptFilePrivate256( outFileName1, outFileName21, PrivateKeyStr111 ) == 0 ) return 0;
	VirtualFree( PrivateKeyStr111, 0, MEM_RELEASE );
	VirtualFree( PublicKeyStr111, 0, MEM_RELEASE );
	VirtualFree( CertificateKeyStr111, 0, MEM_RELEASE );


	//Generate new RSA keys and Encrypt UserFile(any size) with privateKey -> Decrypt UserFile with publicKey and save it to file example
	unsigned char* PrivateKeyStr11 = NULL;
	unsigned char* PublicKeyStr11 = NULL;
	unsigned char* CertificateKeyStr11 = NULL;
	if(GenRSAKeysToMem( &PrivateKeyStr11, &PublicKeyStr11, &CertificateKeyStr11 ) == false ) return 0;
	int fileSize = 20548;
	char fileData[20548];
	memset(fileData, 'A', fileSize );
	char* inFileName = "inFile.txt";
	char* outFileName = "outFile.txt";
	char* outFileName2 = "outFile2.txt";
	FILE* pFile1 = fopen( inFileName, "wb" );
	fwrite( fileData, 1, fileSize, pFile1 );	
	if ( ferror( pFile1 ) )
	{
		fclose( pFile1 );
		VirtualFree( PrivateKeyStr11, 0, MEM_RELEASE );
		VirtualFree( PublicKeyStr11, 0, MEM_RELEASE );
		VirtualFree( CertificateKeyStr11, 0, MEM_RELEASE );
		return 0;
	}
	fclose( pFile1 );
	if( CryptFilePrivate256( inFileName, outFileName, PrivateKeyStr11 ) == 0 ) return 0;
	if( DeCryptFilePublic256( outFileName, outFileName2, PublicKeyStr11 ) == 0 ) return 0;
	VirtualFree( PrivateKeyStr11, 0, MEM_RELEASE );
	VirtualFree( PublicKeyStr11, 0, MEM_RELEASE );
	VirtualFree( CertificateKeyStr11, 0, MEM_RELEASE );


	//Generate new RSA keys and Encrypt UserData(240 byte max) with privateKey -> Decrypt UserData with publicKey and save it to memory example
	unsigned char* PrivateKeyStr1 = NULL;
	unsigned char* PublicKeyStr1 = NULL;
	unsigned char* CertificateKeyStr1 = NULL;
	if(GenRSAKeysToMem( &PrivateKeyStr1, &PublicKeyStr1, &CertificateKeyStr1 ) == false ) return 0;
	char* uncrypteddata1 = "Hello, world!";
	char* crypteddata1 = (char*)VirtualAlloc(  NULL, 256, MEM_COMMIT, PAGE_READWRITE );
	if(crypteddata1 == NULL) return 0;
	int uncrypteddatalen1 = strlen(uncrypteddata1);
	int icryptedlen1 = private_encrypt( (unsigned char*)uncrypteddata1, uncrypteddatalen1, PrivateKeyStr1, (unsigned char*)crypteddata1 );
	if (icryptedlen1 <= 0) return 0;
	char* decrypteddata1 = (char*)VirtualAlloc(  NULL, 256, MEM_COMMIT, PAGE_READWRITE );
	if(decrypteddata1 == NULL) return 0;
	int idecryptedlen1 = public_decrypt( (unsigned char*)crypteddata1, icryptedlen1, PublicKeyStr1, (unsigned char*)decrypteddata1 );
	if (idecryptedlen1 <= 0) return 0;
	VirtualFree( PrivateKeyStr1, 0, MEM_RELEASE );
	VirtualFree( PublicKeyStr1, 0, MEM_RELEASE );
	VirtualFree( CertificateKeyStr1, 0, MEM_RELEASE );


	//Generate new RSA keys and Encrypt UserData(240 byte max) with publicKey -> Decrypt UserData with privateKey and save it to memory example
	unsigned char* PrivateKeyStr2 = NULL;
	unsigned char* PublicKeyStr2 = NULL;
	unsigned char* CertificateKeyStr2 = NULL;
	if(GenRSAKeysToMem( &PrivateKeyStr2, &PublicKeyStr2, &CertificateKeyStr2 ) == false ) return 0;
	char* uncrypteddata2 = "Hello, world!";
	char* crypteddata2 = (char*)VirtualAlloc(  NULL, 256, MEM_COMMIT, PAGE_READWRITE );
	if(crypteddata2 == NULL) return 0;
	int uncrypteddatalen2 = strlen(uncrypteddata2);
	int icryptedlen2 = public_encrypt( (unsigned char*)uncrypteddata2, uncrypteddatalen2, PublicKeyStr2, (unsigned char*)crypteddata2 );
	if (icryptedlen2 <= 0) return 0;
	char* decrypteddata2 = (char*)VirtualAlloc(  NULL, 256, MEM_COMMIT, PAGE_READWRITE );
	if(decrypteddata2 == NULL) return 0;
	int idecryptedlen2 = private_decrypt( (unsigned char*)crypteddata2, icryptedlen2, PrivateKeyStr2, (unsigned char*)decrypteddata2 );
	if (idecryptedlen2 <= 0) return 0;
	VirtualFree( PrivateKeyStr2, 0, MEM_RELEASE );
	VirtualFree( PublicKeyStr2, 0, MEM_RELEASE );
	VirtualFree( CertificateKeyStr2, 0, MEM_RELEASE );

	//Data zip -> unzip example
	char* zipSrc = "Hello, world:, but when I did this I started getting issues with Valgrind reporting reachable blocks at the end of the program, originating from.";
	int zipSrcLen = strlen(zipSrc);
	int zippedLen = 0;
	int unzippedLen = 0;
	char* ZippedChars = compress_stringC ( zipSrc, zipSrcLen, zippedLen );
	if(ZippedChars == NULL) return 0;
	char* unZippedChars = decompress_stringC( ZippedChars, zippedLen, unzippedLen );
	if(unZippedChars == NULL) return 0;
	VirtualFree( ZippedChars, 0, MEM_RELEASE );
	VirtualFree( unZippedChars, 0, MEM_RELEASE );

	//data -> hexeddata and hexeddata -> data example
	char* dataz = "123456789";
	char* hexed = char2charHex ( (unsigned char*) dataz, strlen(dataz) );
	if(hexed == NULL) return 0;
	char* dehexed = charHex2char( (unsigned char*) hexed, strlen(hexed) );
	if(dehexed == NULL) return 0;
	VirtualFree( hexed, 0, MEM_RELEASE );
	VirtualFree( dehexed, 0, MEM_RELEASE );


	//Aes crypt->decrypt any size data example
	unsigned char * key256 = (unsigned char *)"11112222333344445555666677778888"; // 32 byte (256 bit)
	unsigned char * iv128 = (unsigned char *)"1111333355557777"; // 16 byte (128 bit)
	//example data
	char* data = "helloAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAworld";
	int dataLen = strlen(data);
	int cryptedLen = 0;
	int decryptedLen = 0;
	unsigned char *cpp_cipher = aes256_encryptC((unsigned char *)data, dataLen, key256, iv128, cryptedLen);
	if(cpp_cipher == NULL)
	{
		VirtualFree( cpp_cipher, 0, MEM_RELEASE );
		return 0;
	}
	char* base64 = base64Encode( cpp_cipher, cryptedLen );
	if(base64 == NULL)
	{
		VirtualFree( cpp_cipher, 0, MEM_RELEASE );	
		return 0;
	}
	VirtualFree( cpp_cipher, 0, MEM_RELEASE );	
	FILE* pFile = fopen("enc.dat", "wb");
	fwrite(base64, 1, strlen(base64),pFile);
	if ( ferror( pFile ) )
	{
		fclose(pFile);
		VirtualFree( base64, 0, MEM_RELEASE );
		return 0;
	}
	fclose(pFile);	
	unsigned char* debase64 = NULL;
	size_t sLen = strlen(base64);
	int iLen = base64Decode(base64, sLen, &debase64);
	if(debase64 == NULL)
	{
		VirtualFree( base64, 0, MEM_RELEASE );
		return 0;
	}
	VirtualFree( base64, 0, MEM_RELEASE );
	unsigned char *php_cipher = aes256_decryptC(debase64, iLen, key256, iv128, decryptedLen);
	VirtualFree( debase64, 0, MEM_RELEASE );
	if(php_cipher == NULL) return 0;
	FILE* pFileg = fopen("dec.dat", "wb");
	fwrite((char*)php_cipher, 1, decryptedLen, pFileg);
	if ( ferror( pFileg ) )
	{
		fclose(pFileg);
		VirtualFree( php_cipher, 0, MEM_RELEASE );
		return 0;
	}
	fclose(pFileg);
	VirtualFree( php_cipher, 0, MEM_RELEASE );

	return 0;
}
``` 
 
* twitter: @oxfemale
* telegram: @BelousovaAlisa
* email: alice.eas7@gmail.com

