// 
// https://github.com/oxfemale/Cryptone3/
// twitter: @oxfemale
// email: alice.eas7@gmail.com
// telegram: @BelousovaAlisa
//

#include "stdafx.h"
#include "zlib.h"
#include "zip.h"

//Compress char*, gzip style using zlib with given compression level
//return compressed data with size in "unzippedLen" or NULL if error
extern "C" __declspec(dllexport) char* compress_stringC( char* strData, int strDataLen, int &zippedLen )
{
	int compressionlevel = Z_BEST_COMPRESSION;
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
	char* result = NULL;

    if (deflateInit(&zs, compressionlevel) != Z_OK) return NULL;

	std::string my_str(strData, strDataLen);
    zs.next_in = (Bytef*)my_str.data();
	zs.avail_in = my_str.length();

    int ret;
	char outbuffer[32768] = {0};
    std::string outstring;
	

    // retrieve the compressed bytes blockwise
    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = deflate(&zs, Z_FINISH);

        if (outstring.size() < zs.total_out) 
		{
            outstring.append( outbuffer, zs.total_out - outstring.size());
        }
    } while (ret == Z_OK);

    deflateEnd(&zs);

    if (ret != Z_STREAM_END) 
	{
		return NULL;
    }

	zippedLen = outstring.length();
	DWORD dataLen = ( zippedLen + 8);
	result = (char*)VirtualAlloc( NULL, dataLen, MEM_COMMIT, PAGE_READWRITE );
	if ( result == NULL ) return NULL;

	memcpy(result,outstring.c_str(), outstring.length());
	result[outstring.length()] = 0;
	outstring.clear();
	my_str.clear();

    return result;
}

//Decompress char* data by len
//return decompressed data with size in "unzippedLen" or NULL if error
extern "C" __declspec(dllexport) char* decompress_stringC( char* strData, int strDataLen, int &unzippedLen )
{
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
	char* result = NULL;

    if (inflateInit(&zs) != Z_OK) return NULL;


	std::string my_str(strData, strDataLen);
    zs.next_in = (Bytef*)my_str.data();
    zs.avail_in = my_str.size();

    int ret;
    char outbuffer[32768];
    std::string outstring;


    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = inflate(&zs, 0);

        if (outstring.size() < zs.total_out) 
		{
            outstring.append( outbuffer, zs.total_out - outstring.size() );
        }

    } while (ret == Z_OK);

    inflateEnd(&zs);

    if (ret != Z_STREAM_END) 
	{
		return NULL;
    }

	unzippedLen = outstring.length();
	DWORD dataLen = ( unzippedLen + 8);
	result = (char*)VirtualAlloc( NULL, dataLen, MEM_COMMIT, PAGE_READWRITE );
	if ( result == NULL ) return NULL;

	memcpy(result,outstring.c_str(), outstring.length());
	result[outstring.length()] = 0;
	outstring.clear();
	my_str.clear();

    return result;
}


/*
Compress(gzip style) any size data to std::string
*/
extern "C++" __declspec(dllexport) void compress_memory( void *in_data, size_t in_data_size, std::vector<uint8_t> &out_data )
{
 std::vector<uint8_t> buffer;

 const size_t BUFSIZE = 128 * 1024;
 uint8_t temp_buffer[BUFSIZE];

 z_stream strm;
 strm.zalloc = 0;
 strm.zfree = 0;
 strm.next_in = reinterpret_cast<uint8_t *>(in_data);
 strm.avail_in = in_data_size;
 strm.next_out = temp_buffer;
 strm.avail_out = BUFSIZE;

 deflateInit(&strm, Z_BEST_COMPRESSION);

 while (strm.avail_in != 0)
 {
  int res = deflate(&strm, Z_NO_FLUSH);
  assert(res == Z_OK);
  if (strm.avail_out == 0)
  {
   buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE);
   strm.next_out = temp_buffer;
   strm.avail_out = BUFSIZE;
  }
 }

 int deflate_res = Z_OK;
 while (deflate_res == Z_OK)
 {
  if (strm.avail_out == 0)
  {
   buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE);
   strm.next_out = temp_buffer;
   strm.avail_out = BUFSIZE;
  }
  deflate_res = deflate(&strm, Z_FINISH);
 }

 assert(deflate_res == Z_STREAM_END);
 buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE - strm.avail_out);
 deflateEnd(&strm);

 out_data.swap(buffer);
}


/*
Compress std::string, gzip style using zlib with given compression level
return compressed std::string
*/
std::string compress_string(const std::string& str )
{
	int compressionlevel = Z_BEST_COMPRESSION;
    z_stream zs;                        // z_stream is zlib's control structure
    memset(&zs, 0, sizeof(zs));

    if (deflateInit(&zs, compressionlevel) != Z_OK) throw(std::runtime_error("deflateInit failed while compressing."));

    zs.next_in = (Bytef*)str.data();
    zs.avail_in = str.size();   // set the z_stream's input

    int ret;
	char outbuffer[32768] = {0};
    std::string outstring;
	

    // retrieve the compressed bytes blockwise
    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = deflate(&zs, Z_FINISH);

        if (outstring.size() < zs.total_out) {
            // append the block to the output string
            outstring.append( outbuffer, zs.total_out - outstring.size());
        }
    } while (ret == Z_OK);

    deflateEnd(&zs);

    if (ret != Z_STREAM_END) {          // an error occurred that was not EOF
        std::ostringstream oss;
        oss << "Exception during zlib compression: (" << ret << ") " << zs.msg;
        throw(std::runtime_error(oss.str()));
    }

    return outstring;
}

/*
Decompress std::string, gzip style using zlib with given compression level
return decompressed std::string
*/
std::string decompress_string(const std::string& str)
{
    z_stream zs;                        // z_stream is zlib's control structure
    memset(&zs, 0, sizeof(zs));

    if (inflateInit(&zs) != Z_OK)
        throw(std::runtime_error("inflateInit failed while decompressing."));

    zs.next_in = (Bytef*)str.data();
    zs.avail_in = str.size();

    int ret;
    char outbuffer[32768];
    std::string outstring;

    // get the decompressed bytes blockwise using repeated calls to inflate
    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = inflate(&zs, 0);

        if (outstring.size() < zs.total_out) {
            outstring.append(outbuffer,
                             zs.total_out - outstring.size());
        }

    } while (ret == Z_OK);

    inflateEnd(&zs);

    if (ret != Z_STREAM_END) {          // an error occurred that was not EOF
        std::ostringstream oss;
        //oss << "Exception during zlib decompression: (" << ret << ") "<< zs.msg;
        throw(std::runtime_error(oss.str()));
    }

    return outstring;
}

