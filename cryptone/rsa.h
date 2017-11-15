// 
// https://github.com/oxfemale/Cryptone3/
// twitter: @oxfemale
// email: alice.eas7@gmail.com
// telegram: @BelousovaAlisa
//

#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/conf.h"
#include <stdio.h>	
#include <windows.h>
#include <math.h>
#include <iostream>
#include <vector>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <ctime>
//#include "openssl\applink.c"

bool exists_KeyPair( char* FileName1, char* FileName2 );

//write keys to disk
bool write_to_disk(char* ClientPrivateKeyFile, char* ClientPublicKeyFile, char* CertificateFile,  char *PrivateKeyStr, char *PublicKeyStr, char* CertificateKeyStr );

//Ecrypt daya by Public key
//using openssl lib with given key
// unsigned char *encrypted - must be allocate before call public_encrypt()
// return int len of encrypted
extern "C" __declspec(dllexport) int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char* encrypted );

//Decrypt daya by Private key
//using openssl lib with given key
// unsigned char *decrypted - must be allocate before call private_decrypt()
// return int len of decrypted
extern "C" __declspec(dllexport) int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char* decrypted );

//Encrypt daya by Private Key
//using openssl lib with given key
// unsigned char *encrypted - must be allocate before call private_encrypt()
// return int len of encrypted
extern "C" __declspec(dllexport) int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char* encrypted );

//Dencrypt daya by Public Key
//using openssl lib with given key
// unsigned char *decrypted - must be allocate before call public_decrypt()
// return int len of decrypted
extern "C" __declspec(dllexport) int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char* decrypted );

//Encrypt InFile in OutFile by Private key
//using openssl lib with given key
extern "C" __declspec(dllexport) DWORD CryptFilePrivate256(char* FileName, char* NewFileName, unsigned char *privateKey);

//Encrypt InFile in OutFile by Public key
//using openssl lib with given key
extern "C" __declspec(dllexport) DWORD CryptFilePublic256(char* FileName, char* NewFileName, unsigned char *publicKey);

//Dencrypt InFile in OutFile by Private key
//using openssl lib with given key
extern "C" __declspec(dllexport) DWORD DeCryptFilePrivate256(char* FileName, char* NewFileName, unsigned char *privateKey);

//Dencrypt InFile in OutFile by Public key
//using openssl lib with given key
extern "C" __declspec(dllexport) DWORD DeCryptFilePublic256(char* FileName, char* NewFileName, unsigned char *publicKey );

/*
Generate new RSA-2048/sha256 key pairs Public and Private for php encode/decode
using openssl lib with given key
use my function for code/decode:
	public_encrypt()
	public_decrypt()
	private_decrypt()
	private_encrypt()
For php functions on web server, for example on php, server side:
<?php
    $string="Hello, world!";
    $fp=fopen ("client_public.pem","rb");
    $pub_key = fread ($fp,8192);
    fclose($fp);
    //echo $pub_key."<br><br>";
    $PK="";
    $PK=openssl_get_publickey($pub_key);
    if (!$PK) 
    {
	die("Cannot get client public key");
    }
    $finaltext="";
    openssl_public_encrypt($string,$finaltext,$PK);
    if (!empty($finaltext)) 
    {
        openssl_free_key($PK);
        echo "Encryption OK! Safe to file<br> ";
	$ServerMsgFile  = "serverserverMsg.msg";
	$file = fopen($ServerMsgFile,"wb");
	fwrite($file,$finaltext);
	fclose($file);
    }else{
        die("Cannot Encrypt<br>");
    }

    $fpz=fopen ("ClientMessage.crypted","rb");
    $cryptedText=fread ($fpz,8192);
    fclose($fpz);

    $fp=fopen ("server_private.pem","rb");
    $priv_key2=fread ($fp,8192);
    fclose($fp);
    $PK2=openssl_get_privatekey($priv_key2);
    $Crypted=openssl_private_decrypt($cryptedText,$Decrypted,$PK2);
    if (!$Crypted) 
    {
	die("Cannot Decrypt<br>");
    }else{
        echo "<br>Decrypted Data: " . $Decrypted."<br><br>";
    }
?>
*/
extern "C" __declspec(dllexport) bool GenRSAKeysPhp( char* privateFile, char* publicFile, char* CertificateFile, bool IfFilesExistsNotRewrite );


//Generate new RSA-2048/sha256 RSA key pairs Private/Public
//and return it to PrivateKeyStr / PublicKeyStr 
extern "C" __declspec(dllexport) bool GenRSAKeysToMem( unsigned char** PrivateKeyStr, unsigned char** PublicKeyStr, unsigned char** CertificateKeyStr );
