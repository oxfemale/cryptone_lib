// 
// https://github.com/oxfemale/Cryptone3/
// twitter: @oxfemale
// email: alice.eas7@gmail.com
// telegram: @BelousovaAlisa
//

#include "stdafx.h"
#include "rsa.h"
#include "openssl\applink.c"

int padding = RSA_PKCS1_PADDING;

//Generate RSA Public and Private key and save it to 
RSA* createRSA(unsigned char * key, int publicz)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
#ifdef _DEBUG
        printf( "Failed to create key BIO");
#endif
        return 0;
    }
    if(publicz)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
#ifdef _DEBUG
        printf( "Failed to create RSA");
#endif
		return 0;
    }
 
    return rsa;
}

//Ecrypt data by RSA-2048/sha256 Public key
// unsigned char *encrypted - must be allocated before call public_encrypt()
// return encrypted size or -1 if error
extern "C" __declspec(dllexport) int public_encrypt( unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted )
{
    RSA * rsa = createRSA(key,1);
	if(rsa == 0) return -1;
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

//Decrypt data by RSA-2048/sha256 Private key
// unsigned char *decrypted - must be allocated before call private_decrypt()
// return encrypted size or -1 if error
extern "C" __declspec(dllexport) int private_decrypt( unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted )
{
    RSA * rsa = createRSA(key,0);
	if(rsa == 0) return -1;
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

//Encrypt data by RSA-2048/sha256 Private Key
// unsigned char *encrypted - must be allocated before call private_encrypt()
// return encrypted size or -1 if error
extern "C" __declspec(dllexport) int private_encrypt( unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted )
{
    RSA * rsa = createRSA(key,0);
	if(rsa == 0) return -1;
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

// Decrypt data by RSA-2048/sha256 Public Key
// unsigned char *decrypted - must be allocated before call public_decrypt()
// return encrypted size or -1 if error
extern "C" __declspec(dllexport) int public_decrypt( unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted )
{
    RSA * rsa = createRSA(key,1);
	if(rsa == 0) return -1;
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}



//Encrypt any size InFile with RSA-2048/sha256 Private key and put it in the OutFile 
//On error return 0, if ok return 1
extern "C" __declspec(dllexport) DWORD CryptFilePrivate256( char* FileName, char* NewFileName, unsigned char *privateKey )
{
	FILE *pFile = NULL, *pNewFile = NULL;
	long lSize = 0;
	size_t result = 0;
	unsigned char* encrypted = NULL;
	unsigned char* buffer = NULL;
	int encrypted_length = 0;

	encrypted = (unsigned char*) VirtualAlloc(  NULL, 1024, MEM_COMMIT, PAGE_READWRITE );
	if (encrypted == NULL) 
	{
#ifdef _DEBUG
		printf("Error allocate mem encrypted 1024\r\n"); 
#endif
		return 0;
	}
	buffer = (unsigned char*) VirtualAlloc(  NULL, 512, MEM_COMMIT, PAGE_READWRITE );
	if (buffer == NULL) 
	{
#ifdef _DEBUG
		printf("Error allocate mem buffer 512\r\n"); 
#endif
		return 0;
	}

	pFile = fopen ( FileName , "rb" );
	if (pFile == NULL) 
	{
#ifdef _DEBUG
		printf("Error: open file: %s\r\n", FileName);
#endif
		return 0;
	}
	pNewFile = fopen ( NewFileName , "wb" );
	if (pNewFile == NULL) 
	{
#ifdef _DEBUG
		printf("Error: create file: %s\r\n", NewFileName);
#endif
		return 0;
	}

	fseek (pFile , 0 , SEEK_END);
	lSize = ftell (pFile);
	rewind (pFile);
#ifdef _DEBUG
	size_t count = 0;
#endif
	while (!feof (pFile)) 
	{
		result = fread (buffer,1,240,pFile);
		buffer[result] = '\0';
#ifdef _DEBUG
		count = count + result;
		printf("Enc Offset: %d\r\n", count);
#endif
		encrypted_length= private_encrypt(buffer,result,(unsigned char *)privateKey,encrypted);
		if(encrypted_length == -1) 
		{ 
#ifdef _DEBUG
			printf("Private Encrypt failed.\r\n");
#endif
			free(encrypted);
			free(buffer);
			fclose (pFile);
			fclose (pNewFile);
			return 0;
		}
		fwrite(encrypted,1,encrypted_length,pNewFile);
	}
	fclose (pFile);
	fclose (pNewFile);
	VirtualFree( encrypted, 0, MEM_RELEASE );
	VirtualFree( buffer, 0, MEM_RELEASE );
  
	return 1;
}

//Encrypt any size InFile with RSA-2048/sha256 Public key and put it in the OutFile 
//On error return 0, if ok return 1
extern "C" __declspec(dllexport) DWORD CryptFilePublic256( char* FileName, char* NewFileName, unsigned char *publicKey )
{
	FILE *pFile = NULL, *pNewFile = NULL;
	long lSize = 0;
	size_t result = 0;
	unsigned char* encrypted = NULL;
	unsigned char* buffer = NULL;
	int encrypted_length = 0;

	encrypted = (unsigned char*) VirtualAlloc(  NULL, 1024, MEM_COMMIT, PAGE_READWRITE );
	if (encrypted == NULL) 
	{
#ifdef _DEBUG
		printf("Error allocate mem encrypted 1024\r\n"); 
#endif
		return 0;
	}
	buffer = (unsigned char*)  VirtualAlloc(  NULL, 512, MEM_COMMIT, PAGE_READWRITE );
	if (buffer == NULL) 
	{
#ifdef _DEBUG
		printf("Error allocate mem buffer 512\r\n"); 
#endif
		return 0;
	}

	pFile = fopen ( FileName , "rb" );
	if (pFile == NULL) 
	{
#ifdef _DEBUG
		printf("Error: open file: %s\r\n", FileName);
#endif
		return 0;
	}
	pNewFile = fopen ( NewFileName , "wb" );
	if (pNewFile == NULL) 
	{
#ifdef _DEBUG
		printf("Error: create file: %s\r\n", NewFileName);
#endif
		return 0;
	}

	fseek (pFile , 0 , SEEK_END);
	lSize = ftell (pFile);
	rewind (pFile);
#ifdef _DEBUG
	size_t count = 0;
#endif
	while (!feof (pFile)) 
	{
		result = fread (buffer,1,240,pFile);
		buffer[result] = '\0';
#ifdef _DEBUG
		count = count + result;
		printf("Enc Offset: %d\r\n", count);
#endif
		encrypted_length = public_encrypt(buffer,result,(unsigned char *)publicKey,encrypted);
		if(encrypted_length == -1) 
		{ 
#ifdef _DEBUG
			printf("Public Encrypt failed.\r\n");
#endif
			free(encrypted);
			free(buffer);
			fclose (pFile);
			fclose (pNewFile);
			return 0;
		}
		fwrite(encrypted,1,encrypted_length,pNewFile);
	}
	fclose (pFile);
	fclose (pNewFile);
	VirtualFree( encrypted, 0, MEM_RELEASE );
	VirtualFree( buffer, 0, MEM_RELEASE );
  
	return 1;
}

//Dencrypt any size InFile with RSA-2048/sha256 Private key and put it in the OutFile 
//On error return 0, if ok return 1
extern "C" __declspec(dllexport) DWORD DeCryptFilePrivate256( char* FileName, char* NewFileName, unsigned char *privateKey )
{
	FILE *pFile = NULL, *pNewFile = NULL;
	long lSize = 0;
	size_t result = 0;
	unsigned char* decrypted = NULL;
	unsigned char* buffer = NULL;
	int decrypted_length = 0;

	decrypted = (unsigned char*) VirtualAlloc(  NULL, 1024, MEM_COMMIT, PAGE_READWRITE );
	if (decrypted == NULL) 
	{
#ifdef _DEBUG
		printf("Error allocate mem decrypted 1024\r\n"); 
#endif
		return 0;
	}
	buffer = (unsigned char*) VirtualAlloc(  NULL, 512, MEM_COMMIT, PAGE_READWRITE );
	if (buffer == NULL) 
	{
#ifdef _DEBUG
		printf("Error allocate mem buffer 512\r\n"); 
#endif
		return 0;
	}

	pFile = fopen ( FileName , "rb" );
	if (pFile == NULL) 
	{
#ifdef _DEBUG
		printf("Error: open file: %s\r\n", FileName);
#endif
		return 0;
	}
	pNewFile = fopen ( NewFileName , "wb" );
	if (pNewFile == NULL) 
	{
#ifdef _DEBUG
		printf("Error: create file: %s\r\n", NewFileName);
#endif
		return 0;
	}

	fseek (pFile , 0 , SEEK_END);
	lSize = ftell (pFile);
	rewind (pFile);
#ifdef _DEBUG
	DWORD count = 0;
#endif
	while (!feof (pFile)) 
	{
		result = fread (buffer,1,256,pFile);
		if( result == 0 ) break;
		buffer[result] = '\0';
#ifdef _DEBUG
		count = count + result;
		printf("Dec Offset: %d\r\n", count);
#endif
		decrypted_length = private_decrypt(buffer,result,(unsigned char *)privateKey, decrypted);
		if(decrypted_length == -1) 
		{ 
#ifdef _DEBUG
			printf("Private DeCrypt failed.\r\n");
#endif
			VirtualFree( decrypted, 0, MEM_RELEASE );
			VirtualFree( buffer, 0, MEM_RELEASE );
			fclose (pFile);
			fclose (pNewFile);
			return 0;
		}
		fwrite(decrypted,1,decrypted_length,pNewFile);
	}
	fclose (pFile);
	fclose (pNewFile);
	VirtualFree( decrypted, 0, MEM_RELEASE );
	VirtualFree( buffer, 0, MEM_RELEASE );
  
	return 1;
}

//Dencrypt any size InFile with RSA-2048/sha256 Public key and put it in the OutFile 
//On error return 0, if ok return 1
extern "C" __declspec(dllexport) DWORD DeCryptFilePublic256( char* FileName, char* NewFileName, unsigned char *publicKey )
{
	FILE *pFile = NULL, *pNewFile = NULL;
	long lSize = 0;
	size_t result = 0;
	unsigned char* decrypted = NULL;
	unsigned char* buffer = NULL;
	int decrypted_length = 0;

	decrypted = (unsigned char*) VirtualAlloc(  NULL, 1024, MEM_COMMIT, PAGE_READWRITE );
	if (decrypted == NULL) 
	{
#ifdef _DEBUG
		printf("Error allocate mem decrypted 1024\r\n"); 
#endif
		return 0;
	}
	buffer = (unsigned char*) VirtualAlloc(  NULL, 512, MEM_COMMIT, PAGE_READWRITE );
	if (buffer == NULL) 
	{
#ifdef _DEBUG
		printf("Error allocate mem buffer 512\r\n"); 
#endif
		return 0;
	}

	pFile = fopen ( FileName , "rb" );
	if (pFile == NULL) 
	{
#ifdef _DEBUG
		printf("Error: open file: %s\r\n", FileName);
#endif
		return 0;
	}
	pNewFile = fopen ( NewFileName , "wb" );
	if (pNewFile == NULL) 
	{
#ifdef _DEBUG
		printf("Error: create file: %s\r\n", NewFileName);
#endif
		return 0;
	}

	fseek (pFile , 0 , SEEK_END);
	lSize = ftell (pFile);
	rewind (pFile);
#ifdef _DEBUG
	DWORD count = 0;
#endif
	while (!feof (pFile)) 
	{
		result = fread (buffer,1,256,pFile);
		if( result == 0 ) break;
		buffer[result] = '\0';
#ifdef _DEBUG
		count = count + result;
		printf("Dec Offset: %d\r\n", count);
#endif
		decrypted_length = public_decrypt(buffer,result,(unsigned char *)publicKey, decrypted);
		if(decrypted_length == -1) 
		{ 
#ifdef _DEBUG
			printf("Public DeCrypt failed.\r\n");
#endif
			VirtualFree( decrypted, 0, MEM_RELEASE );
			VirtualFree( buffer, 0, MEM_RELEASE );
			fclose (pFile);
			fclose (pNewFile);
			return 0;
		}
		fwrite(decrypted,1,decrypted_length,pNewFile);
	}
	fclose (pFile);
	fclose (pNewFile);
	VirtualFree( decrypted, 0, MEM_RELEASE );
	VirtualFree( buffer, 0, MEM_RELEASE );
  
	return 1;
}



bool exists_KeyPair( char* FileName1, char* FileName2 )
{
    if (FILE *file1 = fopen(FileName1, "rb")) 
	{
        fclose(file1);
		if (FILE *file2 = fopen(FileName2, "rb")) 
		{
			fclose(file2);
		} else {
			return false;    
		}   
        
    } else {
		return false;    
    }
	return true;
}

//write keys to disk
bool write_to_disk(char* ClientPrivateKeyFile, char* ClientPublicKeyFile, char* CertificateFile,  char *PrivateKeyStr, char *PublicKeyStr, char* CertificateKeyStr )
{
    FILE * pkey_file = fopen(ClientPrivateKeyFile, "wb");
    if(!pkey_file)
    {
        return false;
    }

    fwrite( PrivateKeyStr, strlen(PrivateKeyStr), 1, pkey_file );
    fclose (pkey_file);
    
    if (ferror (pkey_file))
    {
        return false;
    }
    
    FILE * pub_file = fopen(ClientPublicKeyFile, "wb");
    if(!pub_file)
    {
        return false;
    }
    
    fwrite( PublicKeyStr, strlen(PublicKeyStr), 1, pub_file );
    fclose(pub_file);
    
    if (ferror (pub_file))
    {
        return false;
    }

    FILE * x509_file = fopen(CertificateFile, "wb");
    if(!x509_file)
    {
        return false;
    }
    
    fwrite( CertificateKeyStr, strlen(CertificateKeyStr), 1, x509_file );
    fclose(x509_file);
    
    if (ferror (x509_file))
    {
        return false;
    }


    return true;
}



/* Generates a self-signed x509 certificate. */
X509 * generate_x509(EVP_PKEY * pkey)
{
    X509 * x509 = X509_new();
    if(!x509)
    {
        return NULL;
    }
    
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    
    X509_set_pubkey(x509, pkey);
    
    X509_NAME * name = X509_get_subject_name(x509);
    
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"CA",        -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"MyCompany", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
    
    X509_set_issuer_name(x509, name);
    
    if(!X509_sign(x509, pkey, EVP_sha1()))
    {
        X509_free(x509);
        return NULL;
    }
    
    return x509;
}

/* Generates a 2048-bit RSA key. */
EVP_PKEY * generate_key()
{
    EVP_PKEY * pkey = EVP_PKEY_new();
    if(!pkey)
    {
        return NULL;
    }
    
    RSA * rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if(!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    return pkey;
}

// Convert Bio to String and return Len in int
int bioToString(BIO *bio, unsigned char **string) 
{
  size_t bioLength = BIO_pending(bio);
  *string = (unsigned char*) VirtualAlloc( NULL, bioLength + 1, MEM_COMMIT, PAGE_READWRITE );

  if(string == NULL) {
    return 0;
  }

  BIO_read(bio, *string, bioLength);

  // Insert the NUL terminator
  (*string)[bioLength] = '\0';

  BIO_free_all(bio);

  return (int)bioLength;
}


//Generate new RSA-2048/sha256 keys Private/Public/Certificate and save it to files
//Set IfFilesExistsNotRewriteset to false for overwrite files
//if Error return false
extern "C" __declspec(dllexport) bool GenRSAKeysPhp( char* privateFile, char* publicFile, char* CertificateFile, bool IfFilesExistsNotRewrite )
{
	if (IfFilesExistsNotRewrite)
	{
		if(exists_KeyPair(privateFile, publicFile )) return false;
	}

	EVP_PKEY * pkey = generate_key();
    if(!pkey)
        return 1;
    
    /* Generate the certificate. */
    X509 * x509 = generate_x509(pkey);
    if(!x509)
    {
        EVP_PKEY_free(pkey);
        return 1;
    }

	BIO *bio1;
	bio1 = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio1, pkey,NULL,NULL,NULL,NULL,NULL);
	unsigned char *PrivateKeyStr = NULL;
	if( bioToString(bio1, &PrivateKeyStr) == 0 ) return 0;
	
    
	
	BIO *bio2;
	unsigned char *CertificateKeyStr = NULL;
	bio2 = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio2, x509);
	if ( bioToString(bio2, &CertificateKeyStr) == 0 ) return 0;

	BIO *bio3;
	unsigned char *PublicKeyStr = NULL;
	bio3 = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio3, pkey);
	if( bioToString(bio3, &PublicKeyStr) == 0 ) return 0;



    bool ret = write_to_disk(privateFile, publicFile, CertificateFile, (char*)PrivateKeyStr, (char*)PublicKeyStr, (char*) CertificateKeyStr );
    EVP_PKEY_free(pkey);
    X509_free(x509);

    VirtualFree( PrivateKeyStr, 0, MEM_RELEASE );
	VirtualFree( PublicKeyStr, 0, MEM_RELEASE );
	VirtualFree( CertificateKeyStr, 0, MEM_RELEASE );

    if(ret)
    {
        return true;
    }
    else
        return false;
}


//Generate new RSA-2048/sha256 RSA key Private/Public/Certificate and save it memory
//if Error return false
extern "C" __declspec(dllexport) bool GenRSAKeysToMem( unsigned char** PrivateKeyStr, unsigned char** PublicKeyStr, unsigned char** CertificateKeyStr )
{
	EVP_PKEY * pkey = generate_key();
    if(!pkey)
        return 1;
    
    /* Generate the certificate. */
    X509 * x509 = generate_x509(pkey);
    if(!x509)
    {
        EVP_PKEY_free(pkey);
        return 1;
    }

	BIO *bio1;
	bio1 = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio1, pkey,NULL,NULL,NULL,NULL,NULL);
	if ( bioToString(bio1, PrivateKeyStr) == 0 ) return 0;
	
	BIO *bio2;
	bio2 = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio2, x509);
	if( bioToString(bio2, CertificateKeyStr) == 0 ) return 0;

	BIO *bio3;
	bio3 = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio3, pkey);
	if( bioToString(bio3, PublicKeyStr) == 0 ) return 0;

    EVP_PKEY_free(pkey);
    X509_free(x509);

    return true;

}
