// Copyright (C) 2014 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#include "test.h"

namespace
{

using namespace lastpass;
using namespace test;

auto const BLOB_BYTES = "\x4c\x50\x41\x56\x00\x00\x00\x03\x31\x31\x38"_s;
auto const ENCRYPTION_KEY = "\x39\xf3\x94\xbd\x59\xd0\xcc\x1e\x2f\xe3\xdb\x0d\x87\x8f\x8f\x77"
                            "\x02\x05\x6f\xd1\x6b\xe7\xe8\xd5\x7d\x64\x53\x7f\xe1\x36\x1a\x18"_s;

BOOST_AUTO_TEST_CASE(parser_extract_chunks)
{
    std::istringstream s(std::string(std::begin(BLOB_BYTES), std::end(BLOB_BYTES)));
    BOOST_CHECK(Parser::extract_chunks(s)
                == (Chunks {{ChunkId::LPAV, {"\x31\x31\x38"_s}}}));
}

BOOST_AUTO_TEST_CASE(parser_extract_chunks_with_filter)
{
    std::istringstream s(std::string(std::begin(BLOB_BYTES), std::end(BLOB_BYTES)));
    BOOST_CHECK(Parser::extract_chunks(s, {ChunkId::LPAV})
                == (Chunks {{ChunkId::LPAV, {"\x31\x31\x38"_s}}}));
}

BOOST_AUTO_TEST_CASE(parser_extract_chunks_accounts)
{
    std::istringstream s(data::BLOB);
    auto chunks = Parser::extract_chunks(s, {ChunkId::ACCT});

    BOOST_CHECK_EQUAL(chunks.size(), 1);
    BOOST_CHECK_EQUAL(chunks[ChunkId::ACCT].size(), data::ACCOUNTS.size());

    auto const &accounts = chunks[ChunkId::ACCT];
    for (size_t i = 0, size = accounts.size(); i < size; ++i)
        check_equal(Parser::parse_account(accounts[i], data::ENCRYPTION_KEY), data::ACCOUNTS[i]);
}

BOOST_AUTO_TEST_CASE(parser_decrypt_aes256_ecb_plain)
{
    std::map<std::string, std::string> const test_cases
    {
        {"", ""},
        {"0123456789", "\xf2\x61\xf1\x20\x0f\x2b\xba\x5e"
                       "\x9e\xab\xbd\x9a\xfc\x6a\xb6\x8b"_s},
        {"All your base are belong to us", "\x04\xd8\x5d\xdd\x0d\xd9\x54\xe0"
                                           "\xf1\x93\xd7\x34\x0b\xbf\x3c\x35"
                                           "\x43\xd3\x21\xf6\x27\x66\xec\x57"
                                           "\x7e\x48\x21\xb4\xc2\x7c\x8d\x53"_s},
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(Parser::decrypt_aes256_ecb_plain(i.second, ENCRYPTION_KEY), i.first);
}

BOOST_AUTO_TEST_CASE(parser_decrypt_aes256_ecb_base64)
{
    std::map<std::string, std::string> const test_cases
    {
        {"", ""},
        {"0123456789", "8mHxIA8rul6eq72a/Gq2iw=="},
        {"All your base are belong to us", "BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM="},
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(Parser::decrypt_aes256_ecb_base64(i.second, ENCRYPTION_KEY), i.first);
}

BOOST_AUTO_TEST_CASE(parser_decrypt_aes256_cbc_plain)
{
    std::map<std::string, std::string> const test_cases
    {
        {
            "0123456789",

            "\x21\x0f\xa1\x88\x8c\xb4\xbc\x61\xb8\xb2\xbb\x07\x99\x70\xa1\x7b"
            "\x77\xa1\x59\xcf\xeb\x60\xf9\xdf\x8b\x2a\x8e\x1b\xc8\x7b\xf0\x37\x57"_s
        },
        {
            "All your base are belong to us",

            "\x21\xca\x24\x0d\x69\xa3\x3a\x42\xad\x2e\x96\x5e\x85\x62\x8b\xeb"
            "\xae\xba\x52\x3e\x9f\x35\x73\xe9\x5f\xa9\x4b\x5a\x5a\x2e\xfb\x52"
            "\xeb\xc1\xbf\x83\xdf\x29\x8f\xe8\x10\x30\x77\xa0\xb4\x4c\x1d\xe1\x48"_s
        }
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(Parser::decrypt_aes256_cbc_plain(i.second, ENCRYPTION_KEY), i.first);
}

BOOST_AUTO_TEST_CASE(parser_decrypt_aes256_cbc_base64)
{
    std::map<std::string, std::string> const test_cases
    {
        {"0123456789",
         "!6TZb9bbrqpocMaNgFjrhjw==|f7RcJ7UowesqGk+um+P5ug=="},
        {"All your base are belong to us",
         "!YFuiAVZgOD2K+s6y8yaMOw==|TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI="},
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(Parser::decrypt_aes256_cbc_base64(i.second, ENCRYPTION_KEY), i.first);
}

}
