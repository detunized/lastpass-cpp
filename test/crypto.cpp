#include "test.h"

namespace
{

using namespace lastpass;
using namespace test;

auto const ENCRYPTION_KEY = "\x39\xf3\x94\xbd\x59\xd0\xcc\x1e\x2f\xe3\xdb\x0d\x87\x8f\x8f\x77"
                            "\x02\x05\x6f\xd1\x6b\xe7\xe8\xd5\x7d\x64\x53\x7f\xe1\x36\x1a\x18"_s;

BOOST_AUTO_TEST_CASE(crypto_pbkdf2_sha256_short)
{
    auto expected = "\x12\x0f\xb6\xcf\xfc\xf8\xb3\x2c\x43\xe7\x22\x52\x56\xc4\xf8\x37"
                    "\xa8\x65\x48\xc9\x2c\xcc\x35\x48\x08\x05\x98\x7c\xb7\x0b\xe1\x7b"_s;
    auto actual = pbkdf2_sha256("password", "salt", 1, expected.size());

    BOOST_CHECK_EQUAL(actual, expected);
}

BOOST_AUTO_TEST_CASE(crypto_pbkdf2_sha256_long)
{
    auto expected = "\x34\x8c\x89\xdb\xcb\xd3\x2b\x2f\x32\xd8\x14\xb8\x11\x6e\x84\xcf"
                    "\x2b\x17\x34\x7e\xbc\x18\x00\x18\x1c\x4e\x2a\x1f\xb8\xdd\x53\xe1"
                    "\xc6\x35\x51\x8c\x7d\xac\x47\xe9"_s;
    auto actual = pbkdf2_sha256("passwordPASSWORDpassword",
                                "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                                4096,
                                expected.size());

    BOOST_CHECK_EQUAL(actual, expected);
}

BOOST_AUTO_TEST_CASE(crypto_sha256)
{
    std::map<std::string, std::string> const test_cases = {
        {
            "abc",

            "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
            "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad"_s
        },
        {
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",

            "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
            "\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1"_s
        },
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(sha256(i.first), i.second);
}

BOOST_AUTO_TEST_CASE(crypto_decrypt_aes256_ecb)
{
    std::map<std::string, std::string> const test_cases {
        {"", ""},
        {"0123456789", "\xf2\x61\xf1\x20\x0f\x2b\xba\x5e\x9e\xab\xbd\x9a\xfc\x6a\xb6\x8b"_s},
        {"All your base are belong to us", "\x04\xd8\x5d\xdd\x0d\xd9\x54\xe0"
                                           "\xf1\x93\xd7\x34\x0b\xbf\x3c\x35"
                                           "\x43\xd3\x21\xf6\x27\x66\xec\x57"
                                           "\x7e\x48\x21\xb4\xc2\x7c\x8d\x53"_s}
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(decrypt_aes256(i.second, ENCRYPTION_KEY, CipherMode::ECB, {}), i.first);
}

BOOST_AUTO_TEST_CASE(crypto_decrypt_aes256_cbc)
{
    std::map<std::string, std::pair<std::string, std::string>> const test_cases {
        {
            "",
            {
                "",
                ""
            }
        },
        {
            "0123456789",
            {
                "\x0f\xa1\x88\x8c\xb4\xbc\x61\xb8\xb2\xbb\x07\x99\x70\xa1\x7b\x77"_s,
                "\xa1\x59\xcf\xeb\x60\xf9\xdf\x8b\x2a\x8e\x1b\xc8\x7b\xf0\x37\x57"_s,
            }
        },
        {
            "All your base are belong to us",
            {
                "\xca\x24\x0d\x69\xa3\x3a\x42\xad\x2e\x96\x5e\x85\x62\x8b\xeb\xae"_s,

                "\xba\x52\x3e\x9f\x35\x73\xe9\x5f\xa9\x4b\x5a\x5a\x2e\xfb\x52\xeb"
                "\xc1\xbf\x83\xdf\x29\x8f\xe8\x10\x30\x77\xa0\xb4\x4c\x1d\xe1\x48"_s,
            }
        },
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(decrypt_aes256(i.second.second, ENCRYPTION_KEY, CipherMode::CBC, i.second.first),
                          i.first);
}

}
