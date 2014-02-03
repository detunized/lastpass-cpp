#pragma once

#include <string>
#include <vector>

namespace lastpass
{

typedef std::vector<uint8_t> Bytes;

Bytes to_bytes(std::string const &text);
std::string to_hex(Bytes const &bytes);
std::string decode_base64(std::string const &base64_text);

}
