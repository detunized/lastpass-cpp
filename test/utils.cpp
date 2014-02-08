#include "test.h"
#include <boost/algorithm/string.hpp>

namespace
{

using namespace lastpass;
using namespace test;

std::map<std::string, std::string> const HEX_TO_RAW = {
    {"", {}},
    {"00", "\x00"_s},
    {"00ff", "\x00\xff"_s},
    {"00010203040506070809", "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"_s},
    {"000102030405060708090a0b0c0d0e0f", "\x00\x01\x02\x03\x04\x05\x06\x07"
                                         "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"_s},
    {"8af633933e96a3c3550c2734bd814195", "\x8a\xf6\x33\x93\x3e\x96\xa3\xc3"
                                         "\x55\x0c\x27\x34\xbd\x81\x41\x95"_s},
};

BOOST_AUTO_TEST_CASE(utils_encode_hex)
{
    for (auto const &i: HEX_TO_RAW)
        BOOST_CHECK_EQUAL(encode_hex(i.second), i.first);
}

BOOST_AUTO_TEST_CASE(utils_decode_hex)
{
    for (auto const &i: HEX_TO_RAW)
    {
        BOOST_CHECK_EQUAL(decode_hex(i.first), i.second);
        BOOST_CHECK_EQUAL(decode_hex(boost::to_upper_copy(i.first)), i.second);
    }
}

BOOST_AUTO_TEST_CASE(utils_decode_hex_throws_on_odd_length)
{
    BOOST_CHECK_THROW(decode_hex("0"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(utils_decode_hex_throws_on_non_hex_characters)
{
    BOOST_CHECK_THROW(decode_hex("xz"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(utils_decode_base64)
{
    BOOST_CHECK(decode_base64("") == "");
    BOOST_CHECK(decode_base64("YQ==") == "\x61"_s);
    BOOST_CHECK(decode_base64("YWI=") == "\x61\x62"_s);
    BOOST_CHECK(decode_base64("YWJj") == "\x61\x62\x63"_s);
    BOOST_CHECK(decode_base64("YWJjZA==") == "\x61\x62\x63\x64"_s);
}

}
