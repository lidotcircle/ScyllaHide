#include "hex.h"
#include <map>
#include <stdexcept>
#include <assert.h>


static const char HexMapping[] = "0123456789ABCDEF";

std::string hex_encode(const void* _src, size_t src_len, const std::string& delim, size_t len_per_line)
{
    const char* src = static_cast<const char*>(_src);
    std::string ans;
    for(size_t i=0;i<src_len;i++) {
        unsigned char c = src[i];
        unsigned char n1 = c & 0xF0;
        n1 >>= 4;
        unsigned char n2 = c & 0x0F;
        ans.push_back(HexMapping[n1]);
        ans.push_back(HexMapping[n2]);
        ans += delim;

        if (len_per_line > 0 && (i+1) % len_per_line == 0)
            ans += "\n";
    }

    return ans;
}

static const std::map<char,char> HexReverseMapping = {
    {'0', 0}, {'1', 1}, {'2', 2}, {'3', 3}, {'4', 4}, {'5', 5}, {'6', 6}, {'7', 7},
    {'8', 8}, {'9', 9}, 
    {'A', 10}, {'B', 11}, {'C', 12}, {'D', 13}, {'E', 14}, {'F', 15},
    {'a', 10}, {'b', 11}, {'c', 12}, {'d', 13}, {'e', 14}, {'f', 15},
};
std::vector<char> hex_decode(const std::string& hexstr)
{
    std::vector<char> ans;
    size_t index = 0;
    auto pull_char = [&](char& c) {
        if (index >= ans.size())
            return false;

        do {
            c = ans[index++];

            if (index >= ans.size())
                return false;
        } while (c == '\n' || c == '\r' || c == ' ');

        return true;
    };

    char c1, c2;
    while(pull_char(c1) && pull_char(c2))
    {
        if (HexReverseMapping.find(c1) == HexReverseMapping.end()
         || HexReverseMapping.find(c2) == HexReverseMapping.end())
        {
            throw std::runtime_error("unexpect char " + std::string(c1, 1) + std::string(c2, 1));
        }
        char c = HexReverseMapping.find(c1)->second;
        c <<= 4;
        c += HexReverseMapping.find(c2)->second;
        ans.push_back(c);
    }

    return ans;
}