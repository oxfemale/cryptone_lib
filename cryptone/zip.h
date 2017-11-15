// 
// https://github.com/oxfemale/Cryptone3/
// twitter: @oxfemale
// email: alice.eas7@gmail.com
// telegram: @BelousovaAlisa
//

#include "stdafx.h"
#include <string>
#include <iostream>
#include <vector>
#include <sstream>
#include <assert.h> 
#include "zlib.h"

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;


/*
Decompress char*, gzip style using zlib with given compression level
return decompressed char*
*/
extern "C" __declspec(dllexport) char* decompress_stringC(char* strData, int strDataLen, int &unzippedLen  );

/*
Compress std::string, gzip style using zlib with given compression level
return compressed std::string
*/
extern "C" __declspec(dllexport) char* compress_stringC(char* strData, int strDataLen, int &zippedLen );

/*
Compress(gzip style) any size data to std::string
*/
extern "C++" __declspec(dllexport) void compress_memory ( void *in_data, size_t in_data_size, std::vector<uint8_t> &out_data );

/*
Compress std::string, gzip style using zlib with given compression level
return compressed std::string
*/
std::string decompress_string ( const std::string &str );

/*
Decompress std::string, gzip style using zlib with given compression level
return decompressed std::string
*/
std::string compress_string ( const std::string &str );
