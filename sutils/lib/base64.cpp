#include "base64.h"
#include <string>
#include <stdexcept>
#include <cassert>
#include <cctype>
using namespace std;

static constexpr char b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static constexpr char reverse_table[128] = {
   64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
   64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
   64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
   64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
   64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
};

string base64_encode(const void* _src, size_t src_len)
{
   auto src = static_cast<const char*>(_src);
   size_t outpos = 0;
   int bits_collected = 0;
   unsigned int accumulator = 0;
   string ret(4 * ((src_len + 2) / 3), '=');

   for (size_t i = 0; i < src_len; ++i) {
      accumulator = (accumulator << 8) | (src[i] & 0xffu);
      bits_collected += 8;
      while (bits_collected >= 6) {
         bits_collected -= 6;
         ret[outpos++] = b64_table[(accumulator >> bits_collected) & 0x3fu];
      }
   }

   if (bits_collected > 0) { // Any trailing bits that are missing.
      assert(bits_collected < 6);
      accumulator <<= 6 - bits_collected;
      ret[outpos++] = b64_table[accumulator & 0x3fu];
   }
   
   assert(outpos % 4 != 1);
   if(outpos % 4 == 2) {
       ret[outpos++] = '=';
       ret[outpos++] = '=';
   } else if (outpos % 4 ==3 ) {
       ret[outpos++] = '=';
   }
   assert(outpos % 4 == 0);

   return ret;
}

vector<char> base64_decode(const std::string& base64_str)
{
   int bits_collected = 0;
   unsigned int accumulator = 0;
   vector<char> ret;

   for (size_t i = 0; i < base64_str.size(); ++i) {
      const int c = base64_str[i];
      if (::std::isspace(c) || c == '=')
          continue;
      if ((c > 127) || (c < 0) || (reverse_table[c] > 63))
          throw std::runtime_error("Illegal character in base64 string");
      accumulator = (accumulator << 6) | reverse_table[c];
      bits_collected += 6;
      if (bits_collected >= 8) {
          bits_collected -= 8;
          auto dc = static_cast<unsigned char>((accumulator >> bits_collected) & 0xffu);
          ret.push_back(dc);
      }
   }

   return ret;
}