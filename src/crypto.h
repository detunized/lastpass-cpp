#pragma once

#include <string>

namespace lastpass
{

std::string pbkdf2_sha256(std::string const &password, std::string const &salt, int iteration_count, size_t size);
std::string sha256(std::string const &text);


enum class CipherMode
{
    CBC,
    ECB,
};

std::string decrypt_aes256(std::string const &data,
                           std::string const &encryption_key,
                           CipherMode mode,
                           std::string const &iv);

}
