#pragma once

#include <string>

namespace lastpass
{

std::string to_hex(std::string const &bytes);
std::string decode_base64(std::string const &base64_text);

}
