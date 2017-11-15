// 
// https://github.com/oxfemale/Cryptone3/
// twitter: @oxfemale
// email: alice.eas7@gmail.com
// telegram: @BelousovaAlisa
//

#include "openssl/bio.h"
#include "openssl/buffer.h"
#include "openssl/evp.h"
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <assert.h> 

static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

int calcDecodeLength(const char *b64input, const size_t length);

bool is_base64(unsigned char c);


//Encode base64 for char* and return new char*
extern "C" __declspec(dllexport) char* base64Encode(const unsigned char *buffer, const size_t length);

//Dencode base64 for char* and return new char*
extern "C" __declspec(dllexport) int base64Decode(const char *b64message, const size_t length, unsigned char **buffer);

//Encode base64 for std::string and return new std::string
std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);

//Dencode base64 for std::string and return new std::string
std::string base64_decode(std::string const& encoded_string);