// 
// https://github.com/oxfemale/Cryptone3/
// twitter: @oxfemale
// email: alice.eas7@gmail.com
// telegram: @BelousovaAlisa
//

#include "stdafx.h"
#include "pemFile.h"

//Read crypted message from binary file
extern "C" __declspec(dllexport) unsigned char* ReadCryptedFile(char* FileName, int &iCryptedMessageLen)
{
	FILE * pFile;
	long lSize;
	int iAllocSize = 0;
	size_t result;
	unsigned char* cMessage = NULL;

	pFile = fopen ( FileName, "rb" );
	if (pFile==NULL)
	{
#ifdef _DEBUG
		printf("Error open file.\r\n");
#endif
		return 0;
	}
	fseek (pFile , 0 , SEEK_END);
	lSize = ftell (pFile);
	iCryptedMessageLen = lSize;
	iAllocSize = lSize*2;
	rewind (pFile);

	cMessage = (unsigned char*)VirtualAlloc( NULL, (iAllocSize+16), MEM_COMMIT, PAGE_READWRITE );

  	if (cMessage == NULL) 
	{
#ifdef _DEBUG
		printf("Error allocate iAllocSize+16 byte\r\n");
#endif
		return 0;
	}
	//memset(cMessage,0,8000);
	result = fread (cMessage,1,lSize,pFile);
	if (result != lSize) 
	{
#ifdef _DEBUG
		printf("Error fread from file .\r\n");
#endif
		return 0;
	}
	fclose (pFile);
	cMessage[iCryptedMessageLen] = 0;
	return cMessage;
}


//Read Public key from file and return it to char* 
extern "C" __declspec(dllexport) char* ReadPublicPemFile(char* PubPem)
{
	FILE * pFile;
	long lSize;
	size_t result;
	char* publicKey = NULL;

	pFile = fopen ( PubPem, "rb" );
	if (pFile==NULL)
	{
#ifdef _DEBUG
		printf("Error open Public key file.\r\n");
#endif
		return 0;
	}
	fseek (pFile , 0 , SEEK_END);
	lSize = ftell (pFile);
	rewind (pFile);

	publicKey = ( char*)VirtualAlloc( NULL, (8192*2), MEM_COMMIT, PAGE_READWRITE );
  	if (publicKey == NULL) 
	{
#ifdef _DEBUG
		printf("Error allocate 8192*2 byte mem for publicKey.\r\n");
#endif
		return 0;
	}
	//memset(publicKey,0,8000);
	result = fread (publicKey,1,lSize,pFile);
	if (result != lSize) 
	{
#ifdef _DEBUG
		printf("Error fread Public Key from file .\r\n");
#endif
		return 0;
	}
	fclose (pFile);
	publicKey[lSize] = 0;
	return publicKey;
}

//Read Private key from file and return it to char*
extern "C" __declspec(dllexport) char* ReadPrivatePemFile(char* PubPem)
{
	FILE * pFile;
	long lSize;
	size_t result;
	char* privateKey = NULL;

	pFile = fopen ( PubPem, "rb" );
	if (pFile==NULL)
	{
#ifdef _DEBUG
		printf("Error open Public key file.\r\n");
#endif
		return 0;
	}
	fseek (pFile , 0 , SEEK_END);
	lSize = ftell (pFile);
	rewind (pFile);

	privateKey = ( char*)VirtualAlloc( NULL, (8192*2), MEM_COMMIT, PAGE_READWRITE );
  	if (privateKey == NULL) 
	{
#ifdef _DEBUG
		printf("Error allocate 8192*2 byte mem for publicKey.\r\n");
#endif
		return 0;
	}
	//memset(privateKey,0,8000);
	result = fread (privateKey,1,lSize,pFile);
	if (result != lSize) 
	{
#ifdef _DEBUG
		printf("Error fread Public Key from file .\r\n");
#endif
		return 0;
	}
	fclose (pFile);
	privateKey[lSize] = 0;
	return privateKey;
}

