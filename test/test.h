#pragma once

#include <string>

namespace lastpass
{

namespace test
{

inline std::string operator "" _s(char const *chars, size_t count)
{
    return {chars, chars + count};
}

}

}
