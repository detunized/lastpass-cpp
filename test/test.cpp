#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE lastpass
#include <boost/test/unit_test.hpp>

#include <boost/format.hpp>

#include "../src/fetcher.h"
#include "../src/session.h"

#define FS(format_string, arguments) (str(boost::format(format_string) % arguments))

using namespace lastpass;

namespace
{

std::string const USERNAME = "username";
std::string const PASSWORD = "password";
std::string const SESSION_ID = "53ru,Hb713QnEVM5zWZ16jMvxS0";
int const KEY_ITERATION_COUNT = 5000;

std::string const LOGIN_URL = "https://lastpass.com/login.php";
std::string const ITERATIONS_URL = "https://lastpass.com/iterations.php";
std::string const HASH = "7880a04588cfab954aa1a2da98fd9c0d2c6eba4c53e36a94510e6dbf30759256";

}

BOOST_AUTO_TEST_CASE(Session_getters)
{
    Session session("id", 1000);
    BOOST_CHECK_EQUAL(session.id(), "id");
    BOOST_CHECK_EQUAL(session.key_iteration_count(), 1000);
}

BOOST_AUTO_TEST_CASE(Fetcher_login_with_iterations)
{
    class MockWebClient: public WebClient
    {
    public:
        virtual std::string get(std::string const &url, Values const &values, Values const &cookies) override
        {
            BOOST_FAIL("Should not be called");
            return "";
        }

        virtual std::string post(std::string const &url, Values const &values, Values const &cookies) override
        {
            Values expected_values = {
                {"method", "mobile"},
                {"web", "1"},
                {"xml", "1"},
                {"username", USERNAME},
                {"hash", HASH},
                {"iterations", std::to_string(KEY_ITERATION_COUNT)}
            };

            BOOST_CHECK_EQUAL(url, LOGIN_URL);
            BOOST_CHECK(values == expected_values);
            BOOST_CHECK(cookies.empty());

            return FS("<ok sessionid=\"%1%\" />", SESSION_ID);
        }

    } mwc;

    auto session = Fetcher::login(USERNAME, PASSWORD, KEY_ITERATION_COUNT, mwc);
    BOOST_CHECK_EQUAL(session.id(), SESSION_ID);
    BOOST_CHECK_EQUAL(session.key_iteration_count(), KEY_ITERATION_COUNT);
}

BOOST_AUTO_TEST_CASE(Fetcher_request_iteration_count)
{
    // TODO: Remove code duplication!

    class MockWebClient: public WebClient
    {
    public:
        virtual std::string get(std::string const &url, Values const &values, Values const &cookies) override
        {
            BOOST_FAIL("Should not be called");
            return "";
        }

        virtual std::string post(std::string const &url, Values const &values, Values const &cookies) override
        {
            Values expected_values = {{"email", USERNAME}};

            BOOST_CHECK_EQUAL(url, ITERATIONS_URL);
            BOOST_CHECK(values == expected_values);
            BOOST_CHECK(cookies.empty());

            return std::to_string(KEY_ITERATION_COUNT);
        }

    } mwc;

    BOOST_CHECK_EQUAL(Fetcher::request_iteration_count(USERNAME, mwc), KEY_ITERATION_COUNT);
}

BOOST_AUTO_TEST_CASE(Fetcher_make_key)
{
    std::map<int, std::vector<uint8_t>> test_cases = {
        {1,   {0x0b, 0xf0, 0x61, 0xd9, 0x21, 0x96, 0xc4, 0x8f,
               0x09, 0x0e, 0xee, 0x78, 0x0d, 0xb6, 0xe9, 0x57,
               0xc2, 0x7d, 0xc1, 0xae, 0xa9, 0x29, 0xb7, 0xac,
               0x21, 0xbf, 0x4c, 0x01, 0x79, 0x1e, 0x17, 0x76}},
        {5,   {0xa4, 0x4f, 0x60, 0xa1, 0xac, 0xd2, 0x09, 0x1a,
               0xa7, 0x5b, 0x07, 0x22, 0xc5, 0x63, 0x38, 0x34,
               0x72, 0x63, 0x58, 0xcb, 0xc1, 0xe5, 0x3d, 0x79,
               0x74, 0xc8, 0x5e, 0xea, 0xe8, 0x35, 0xa5, 0x98}},
        {50,  {0x1b, 0x02, 0x3c, 0xfe, 0x43, 0x72, 0xd4, 0xd8,
               0xc8, 0x7d, 0xed, 0xd9, 0xd1, 0x50, 0x19, 0x7c,
               0x5e, 0xfc, 0xf7, 0x7f, 0x14, 0x56, 0xe0, 0xa2,
               0xeb, 0x10, 0x0b, 0xdc, 0xc2, 0x41, 0xbb, 0x1d}},
        {500, {0x39, 0xf3, 0x94, 0xbd, 0x59, 0xd0, 0xcc, 0x1e,
               0x2f, 0xe3, 0xdb, 0x0d, 0x87, 0x8f, 0x8f, 0x77,
               0x02, 0x05, 0x6f, 0xd1, 0x6b, 0xe7, 0xe8, 0xd5,
               0x7d, 0x64, 0x53, 0x7f, 0xe1, 0x36, 0x1a, 0x18}},
    };

    for (auto const &i: test_cases)
        BOOST_CHECK(Fetcher::make_key("postlass@gmail.com", "pl1234567890", i.first) == i.second);
}

BOOST_AUTO_TEST_CASE(Fetcher_make_hash)
{
    std::map<int, std::string> test_cases = {
        {1, "a1943cfbb75e37b129bbf78b9baeab4ae6dd08225776397f66b8e0c7a913a055"},
        {5, "a95849e029a7791cfc4503eed9ec96ab8675c4a7c4e82b00553ddd179b3d8445"},
        {50, "1d5bc0d636da4ad469cefe56c42c2ff71589facb9c83f08fcf7711a7891cc159"},
        {500, "3139861ae962801b59fc41ff7eeb11f84ca56d810ab490f0d8c89d9d9ab07aa6"},
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(Fetcher::make_hash("postlass@gmail.com", "pl1234567890", i.first), i.second);
}

BOOST_AUTO_TEST_CASE(Fetcher_pbkdf2_sha256_short)
{
    std::vector<uint8_t> expected {0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
                                   0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
                                   0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
                                   0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b};
    auto actual = Fetcher::pbkdf2_sha256(Fetcher::to_bytes("password"),
                                         Fetcher::to_bytes("salt"),
                                         1,
                                         expected.size());

    BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(Fetcher_pbkdf2_sha256_long)
{
    std::vector<uint8_t> expected {0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f,
                                   0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
                                   0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18,
                                   0x1c, 0x4e, 0x2a, 0x1f, 0xb8, 0xdd, 0x53, 0xe1,
                                   0xc6, 0x35, 0x51, 0x8c, 0x7d, 0xac, 0x47, 0xe9};
    auto actual = Fetcher::pbkdf2_sha256(Fetcher::to_bytes("passwordPASSWORDpassword"),
                                         Fetcher::to_bytes("saltSALTsaltSALTsaltSALTsaltSALTsalt"),
                                         4096,
                                         expected.size());

    BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(Fetcher_sha256)
{
    std::map<std::string, std::vector<uint8_t>> const test_cases = {
        {
            "abc",
            {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
             0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
             0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
             0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad}
        },
        {
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            {0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
             0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
             0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
             0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1}
        },
    };

    for (auto const &i: test_cases)
        BOOST_CHECK(Fetcher::sha256(i.first) == i.second);
}

BOOST_AUTO_TEST_CASE(Fetcher_to_bytes)
{
    std::map<std::string, std::vector<uint8_t>> const test_cases = {
        {"", {}},
        {"Hello, UTF-8!", {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x55, 0x54, 0x46, 0x2d, 0x38, 0x21}},
    };

    for (auto const &i: test_cases)
        BOOST_CHECK(Fetcher::to_bytes(i.first) == i.second);
}

BOOST_AUTO_TEST_CASE(Fetcher_to_hex)
{
    std::map<std::string, std::vector<uint8_t>> const test_cases = {
        {"", {}},
        {"00", {0}},
        {"00ff", {0, 255}},
        {"00010203040506070809", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
        {"000102030405060708090a0b0c0d0e0f", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
        {"8af633933e96a3c3550c2734bd814195", {0x8a, 0xf6, 0x33, 0x93, 0x3e, 0x96, 0xa3, 0xc3,
                                              0x55, 0x0c, 0x27, 0x34, 0xbd, 0x81, 0x41, 0x95}},
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(Fetcher::to_hex(i.second), i.first);
}
