// 
// https://github.com/oxfemale/Cryptone3/
// twitter: @oxfemale
// email: alice.eas7@gmail.com
// telegram: @BelousovaAlisa
//

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


//Read crypted message from binary file
extern "C" __declspec(dllexport) unsigned char* ReadCryptedFile(char* FileName, int &iCryptedMessageLen);

//Read Public key from file and return it to char* 
extern "C" __declspec(dllexport) char* ReadPublicPemFile(char* PubPem);

//Read Private key from file and return it to char*
extern "C" __declspec(dllexport) char* ReadPrivatePemFile(char* PubPem);
