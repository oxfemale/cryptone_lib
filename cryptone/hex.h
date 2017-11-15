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
#include <algorithm>
#include <stdexcept>



/*
Convert char* hex hex format->char*, for example "313233" in hex -> "123"
return char*
*/
extern "C" __declspec(dllexport) char* charHex2char( unsigned char* data, int dataLen );

/*
Convert char* -> char* in hex format, for example "123" -> "313233" in hex
return char*
*/
extern "C" __declspec(dllexport) char* char2charHex ( unsigned char* zip, int size );

