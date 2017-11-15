// 
// https://github.com/oxfemale/Cryptone3/
// twitter: @oxfemale
// email: alice.eas7@gmail.com
// telegram: @BelousovaAlisa
//

#include "stdafx.h"
#include "base64.h"

int calcDecodeLength(const char *b64input, const size_t length) {
  unsigned int padding = 0;

  // Check for trailing '=''s as padding
  if(b64input[length - 1] == '=' && b64input[length - 2] == '=') {
    padding = 2;
  } else if (b64input[length - 1] == '=') {
    padding = 1;
  }

  return (int)length * 0.75 - padding;
}

static inline bool is_base64(unsigned char c) 
{
  return (isalnum(c) || (c == '+') || (c == '/'));
}

//Encode base64 for char* and return new char*
//return base64 string or NULL if error
extern "C" __declspec(dllexport) char* base64Encode( const unsigned char *message, const size_t length ) 
{
  int encodedSize = 4 * ceil((double)length / 3);
  char *b64text = NULL;
  
  b64text = ( char*)VirtualAlloc( NULL, encodedSize + 1, MEM_COMMIT, PAGE_READWRITE );
  if( b64text == NULL ) return NULL;

  int codedLen = 0;

  if(b64text == NULL) {
    //fprintf(stderr, "Failed to allocate memory\n");
    return NULL;
  }

  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  BIO_write(bio, message, length);
  BIO_flush(bio);

  BUF_MEM *bufferPtr;
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);

  BIO_free_all(bio);
  b64text = (*bufferPtr).data;
  codedLen =  (*bufferPtr).length;
  b64text[codedLen] = 0;

  return b64text;
}

//Decode base64 for char* and return new char*
//return decoded data size and data in "buffer", On Error return NULL in "buffer"
extern "C" __declspec(dllexport) int base64Decode( const char *b64message, const size_t length, unsigned char **buffer ) 
{
  int decodedLength = calcDecodeLength(b64message, length);
  *buffer = (unsigned char*)VirtualAlloc( NULL, decodedLength + 1, MEM_COMMIT, PAGE_READWRITE );


  if(*buffer == NULL) {
    //fprintf(stderr, "Failed to allocate memory\n");
    return NULL;
  }

  BIO *bio = BIO_new_mem_buf(b64message, -1);
  BIO *b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  decodedLength = BIO_read(bio, *buffer, strlen(b64message));
  (*buffer)[decodedLength] = '\0';

  BIO_free_all(bio);

  return decodedLength;
}

//Encode base64 for std::string and return new std::string
std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) 
{
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;

}

//Dencode base64 for std::string and return new std::string
std::string base64_decode(std::string const& encoded_string) 
{
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}
