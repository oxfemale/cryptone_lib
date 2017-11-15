// 
// https://github.com/oxfemale/Cryptone3/
// twitter: @oxfemale
// email: alice.eas7@gmail.com
// telegram: @BelousovaAlisa
//

#include "stdafx.h"
#include "hex.h"

//Convert char* hex hex format->char*, for example "313233" in hex -> "123"
//return char* text or NULL if error
extern "C" __declspec(dllexport) char* charHex2char( unsigned char* data, int dataLen )
{
    static const char* const lut = "0123456789ABCDEF";
	char* result = NULL;
    if (dataLen & 1) return NULL;

    std::string output;
    output.reserve(dataLen / 2);
    for (size_t i = 0; i < dataLen; i += 2)
    {
        char a = data[i];
        const char* p = std::lower_bound(lut, lut + 16, a);
        if (*p != a) 
		{
			output.clear();
			return NULL;
		}

        char b = data[i + 1];
        const char* q = std::lower_bound(lut, lut + 16, b);
        if (*q != b) 
		{
			output.clear();
			return NULL;
		}

        output.push_back(((p - lut) << 4) | (q - lut));
    }

	result = (char*)VirtualAlloc( NULL, dataLen, MEM_COMMIT, PAGE_READWRITE );
	if ( result == NULL ) 
	{
		output.clear();
		return NULL;
	}

	memcpy(result,output.c_str(), output.length());
	result[output.length()] = 0;
	output.clear();

	return result;
}


//Convert char* -> char* in hex format, for example "123" -> "313233" in hex
//return char* text or NULL if error
extern "C" __declspec(dllexport) char* char2charHex ( unsigned char* zip, int size )
{
	char const hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',   'B','C','D','E','F'};
	char* result = NULL;
	int memSize = ((size*2)+8);
	std::string stro;
	for (int i = 0; i < size; ++i) 
	{
		const char ch = zip[i];
		stro.append(&hex[(ch  & 0xF0) >> 4], 1);
		stro.append(&hex[ch & 0xF], 1);
	}

	result = (char*)VirtualAlloc( NULL, memSize, MEM_COMMIT, PAGE_READWRITE );
	if ( result == NULL ) return NULL;

	memcpy(result,stro.c_str(), stro.length());
	result[stro.length()] = 0;
	stro.clear();
	return result;
}


/*
Convert std::string -> std::string in hex format, for example "123" -> "313233" in hex
return std::string
*/
std::string stdString2stdStringHex ( std::string zipped )
{
	char const hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',   'B','C','D','E','F'};
	int size = zipped.length();
	std::string stro;
	for (int i = 0; i < size; ++i) 
	{
		const char ch = zipped[i];
		stro.append(&hex[(ch  & 0xF0) >> 4], 1);
		stro.append(&hex[ch & 0xF], 1);
	}
	return stro;
}

/*
Convert std::string in hex format->std::string, for example "313233" in hex -> "123"
return std::string
*/
std::string stdStringHex2stdString(const std::string input)
{
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();
    if (len & 1) throw std::invalid_argument("odd length");

    std::string output;
    output.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2)
    {
        char a = input[i];
        const char* p = std::lower_bound(lut, lut + 16, a);
        if (*p != a) throw std::invalid_argument("not a hex digit");

        char b = input[i + 1];
        const char* q = std::lower_bound(lut, lut + 16, b);
        if (*q != b) throw std::invalid_argument("not a hex digit");

        output.push_back(((p - lut) << 4) | (q - lut));
    }
    return output;
}
