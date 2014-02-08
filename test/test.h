#pragma once

#include "../src/account.h"
#include "../src/blob.h"
#include "../src/crypto.h"
#include "../src/curlwebclient.h"
#include "../src/fetcher.h"
#include "../src/parser.h"
#include "../src/session.h"
#include "../src/utils.h"
#include "../src/vault.h"
#include "../src/xml.h"

#include <boost/test/unit_test.hpp>
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
