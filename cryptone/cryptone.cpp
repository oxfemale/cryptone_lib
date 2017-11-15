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
#include "base64.h"
#include "zip.h"
#include "hex.h"
#include "aes256.h"
#include "rsa.h"
#include "pemFile.h"
//#include "openssl\applink.c"

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
