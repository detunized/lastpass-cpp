#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE lastpass
#include <boost/test/unit_test.hpp>

#include "../src/fetcher.h"

using namespace lastpass;

BOOST_AUTO_TEST_CASE(Fetcher_make_hash)
{
    BOOST_CHECK_EQUAL(Fetcher::make_hash("postlass@gmail.com", "pl1234567890", 1),
                      "a1943cfbb75e37b129bbf78b9baeab4ae6dd08225776397f66b8e0c7a913a055");
}

BOOST_AUTO_TEST_CASE(Fetcher_pbkdf2_sha256_short)
{
    std::vector<uint8_t> expected {0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
                                   0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
                                   0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
                                   0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b};
    auto actual = Fetcher::pbkdf2_sha256("password", "salt", 1, expected.size());

    BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(Fetcher_pbkdf2_sha256_long)
{
    std::vector<uint8_t> expected {0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f,
                                   0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
                                   0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18,
                                   0x1c, 0x4e, 0x2a, 0x1f, 0xb8, 0xdd, 0x53, 0xe1,
                                   0xc6, 0x35, 0x51, 0x8c, 0x7d, 0xac, 0x47, 0xe9};
    auto actual = Fetcher::pbkdf2_sha256("passwordPASSWORDpassword",
                                         "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                                         4096,
                                         expected.size());

    BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(Fetcher_sha256_short)
{
    std::vector<uint8_t> expected {0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
                                   0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
                                   0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
                                   0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD};
    auto actual = Fetcher::sha256("abc");

    BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(Fetcher_sha256_long)
{
    std::vector<uint8_t> expected {0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
                                   0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
                                   0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
                                   0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1};
    auto actual = Fetcher::sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");

    BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
}
