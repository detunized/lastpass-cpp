#pragma once

#include <string>

namespace lastpass
{

std::string pbkdf2_sha256(std::string const &password, std::string const &salt, int iteration_count, size_t size);
std::string sha256(std::string const &text);

}
