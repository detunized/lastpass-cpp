#pragma once

#include "utils.h"

namespace lastpass
{

Bytes pbkdf2_sha256(Bytes const &password, Bytes const &salt, int iteration_count, size_t size);
Bytes sha256(std::string const &text);

}
