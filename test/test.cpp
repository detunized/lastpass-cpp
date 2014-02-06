// TODO: Split this module into separate files!

#include "testdata.h"

#include "../src/account.h"
#include "../src/crypto.h"
#include "../src/fetcher.h"
#include "../src/parser.h"
#include "../src/session.h"
#include "../src/utils.h"

#include <boost/format.hpp>

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE lastpass
#include <boost/test/unit_test.hpp>

#define C(dd) (static_cast<char>(0x##dd))
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
std::string const ACCOUNT_DOWNLOAD_URL = "https://lastpass.com/getaccts.php";
std::string const HASH = "7880a04588cfab954aa1a2da98fd9c0d2c6eba4c53e36a94510e6dbf30759256";
std::string const BLOB = "TFBBVgAAAAMxMTg=";
std::string const BLOB_BYTES {C(4c), C(50), C(41), C(56), C(00), C(00), C(00), C(03), C(31), C(31), C(38)};
std::string const ENCRYPTION_KEY {C(39), C(f3), C(94), C(bd), C(59), C(d0), C(cc), C(1e),
                                  C(2f), C(e3), C(db), C(0d), C(87), C(8f), C(8f), C(77),
                                  C(02), C(05), C(6f), C(d1), C(6b), C(e7), C(e8), C(d5),
                                  C(7d), C(64), C(53), C(7f), C(e1), C(36), C(1a), C(18)};

}

BOOST_AUTO_TEST_CASE(Account_getters)
{
    Account account("id", "name", "username", "password", "url", "group");

    BOOST_CHECK_EQUAL(account.id(), "id");
    BOOST_CHECK_EQUAL(account.name(), "name");
    BOOST_CHECK_EQUAL(account.username(), "username");
    BOOST_CHECK_EQUAL(account.password(), "password");
    BOOST_CHECK_EQUAL(account.url(), "url");
    BOOST_CHECK_EQUAL(account.group(), "group");
}

BOOST_AUTO_TEST_CASE(Session_getters)
{
    Session session(SESSION_ID, KEY_ITERATION_COUNT);
    BOOST_CHECK_EQUAL(session.id(), SESSION_ID);
    BOOST_CHECK_EQUAL(session.key_iteration_count(), KEY_ITERATION_COUNT);
}

BOOST_AUTO_TEST_CASE(Blob_getters)
{
    Blob blob(BLOB_BYTES, KEY_ITERATION_COUNT);
    BOOST_CHECK(blob.bytes() == BLOB_BYTES);
    BOOST_CHECK_EQUAL(blob.key_iteration_count(), KEY_ITERATION_COUNT);
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

BOOST_AUTO_TEST_CASE(Fetcher_fetch)
{
    // TODO: Remove code duplication!

    class MockWebClient: public WebClient
    {
    public:
        virtual std::string get(std::string const &url, Values const &values, Values const &cookies) override
        {
            Values expected_values = {{"mobile", "1"}, {"b64", "1"}, {"hash", "0.0"}};
            Values expected_cookies = {{"PHPSESSID", SESSION_ID}};

            BOOST_CHECK_EQUAL(url, ACCOUNT_DOWNLOAD_URL);
            BOOST_CHECK(values == expected_values);
            BOOST_CHECK(cookies == expected_cookies);

            return BLOB;
        }

        virtual std::string post(std::string const &url, Values const &values, Values const &cookies) override
        {
            BOOST_FAIL("Should not be called");
            return "";
        }

    } mwc;

    auto blob = Fetcher::fetch(Session(SESSION_ID, KEY_ITERATION_COUNT), mwc);
    BOOST_CHECK(blob.bytes() == BLOB_BYTES);
    BOOST_CHECK_EQUAL(blob.key_iteration_count(), KEY_ITERATION_COUNT);
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
    std::map<int, std::string> test_cases = {
        {1,   {C(0b), C(f0), C(61), C(d9), C(21), C(96), C(c4), C(8f),
               C(09), C(0e), C(ee), C(78), C(0d), C(b6), C(e9), C(57),
               C(c2), C(7d), C(c1), C(ae), C(a9), C(29), C(b7), C(ac),
               C(21), C(bf), C(4c), C(01), C(79), C(1e), C(17), C(76)}},
        {5,   {C(a4), C(4f), C(60), C(a1), C(ac), C(d2), C(09), C(1a),
               C(a7), C(5b), C(07), C(22), C(c5), C(63), C(38), C(34),
               C(72), C(63), C(58), C(cb), C(c1), C(e5), C(3d), C(79),
               C(74), C(c8), C(5e), C(ea), C(e8), C(35), C(a5), C(98)}},
        {50,  {C(1b), C(02), C(3c), C(fe), C(43), C(72), C(d4), C(d8),
               C(c8), C(7d), C(ed), C(d9), C(d1), C(50), C(19), C(7c),
               C(5e), C(fc), C(f7), C(7f), C(14), C(56), C(e0), C(a2),
               C(eb), C(10), C(0b), C(dc), C(c2), C(41), C(bb), C(1d)}},
        {500, {C(39), C(f3), C(94), C(bd), C(59), C(d0), C(cc), C(1e),
               C(2f), C(e3), C(db), C(0d), C(87), C(8f), C(8f), C(77),
               C(02), C(05), C(6f), C(d1), C(6b), C(e7), C(e8), C(d5),
               C(7d), C(64), C(53), C(7f), C(e1), C(36), C(1a), C(18)}},
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

BOOST_AUTO_TEST_CASE(Parser_extract_chunks)
{
    std::istringstream s(std::string(std::begin(BLOB_BYTES), std::end(BLOB_BYTES)));
    BOOST_CHECK(Parser::extract_chunks(s) == (Chunks {{'LPAV', {{C(31), C(31), C(38)}}}}));
}

BOOST_AUTO_TEST_CASE(Parser_extract_chunks_with_filter)
{
    std::istringstream s(std::string(std::begin(BLOB_BYTES), std::end(BLOB_BYTES)));
    BOOST_CHECK(Parser::extract_chunks(s, {'LPAV'}) == (Chunks {{'LPAV', {{C(31), C(31), C(38)}}}}));
}

BOOST_AUTO_TEST_CASE(Parser_extract_chunks_accounts)
{
    std::istringstream s(test::BLOB);
    auto chunks = Parser::extract_chunks(s, {'ACCT'});
    BOOST_CHECK_EQUAL(chunks.size(), 1);
    BOOST_CHECK_EQUAL(chunks['ACCT'].size(), test::ACCOUNTS.size());

    auto const &accounts = chunks['ACCT'];
    for (size_t i = 0, size = accounts.size(); i < size; ++i)
    {
        auto account = Parser::parse_account(accounts[i], test::ENCRYPTION_KEY);
        auto const &expected = test::ACCOUNTS[i];

        BOOST_CHECK_EQUAL(account.id(), expected.id);
        BOOST_CHECK_EQUAL(account.name(), expected.name);
        BOOST_CHECK_EQUAL(account.username(), expected.username);
        BOOST_CHECK_EQUAL(account.password(), expected.password);
        //BOOST_CHECK_EQUAL(account.url(), expected.url); // TODO: URLs are not decoded yet.
        BOOST_CHECK_EQUAL(account.group(), expected.group);
    }
}

BOOST_AUTO_TEST_CASE(Parser_decrypt_aes256_ecb_plain)
{
    std::map<std::string, std::string> const test_cases
    {
        {"", ""},
        {"0123456789", {C(f2), C(61), C(f1), C(20), C(0f), C(2b), C(ba), C(5e),
                        C(9e), C(ab), C(bd), C(9a), C(fc), C(6a), C(b6), C(8b)}},
        {"All your base are belong to us", {C(04), C(d8), C(5d), C(dd), C(0d), C(d9), C(54), C(e0),
                                            C(f1), C(93), C(d7), C(34), C(0b), C(bf), C(3c), C(35),
                                            C(43), C(d3), C(21), C(f6), C(27), C(66), C(ec), C(57),
                                            C(7e), C(48), C(21), C(b4), C(c2), C(7c), C(8d), C(53)}},
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(Parser::decrypt_aes256_ecb_plain(i.second, ENCRYPTION_KEY), i.first);
}

BOOST_AUTO_TEST_CASE(Parser_decrypt_aes256_ecb_base64)
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

BOOST_AUTO_TEST_CASE(Parser_decrypt_aes256_cbc_plain)
{
    std::map<std::string, std::string> const test_cases
    {
        {
            "0123456789",
            {C(21), C(0f), C(a1), C(88), C(8c), C(b4), C(bc), C(61),
             C(b8), C(b2), C(bb), C(07), C(99), C(70), C(a1), C(7b),
             C(77), C(a1), C(59), C(cf), C(eb), C(60), C(f9), C(df),
             C(8b), C(2a), C(8e), C(1b), C(c8), C(7b), C(f0), C(37),
             C(57)}
        },
        {
            "All your base are belong to us",
            {C(21), C(ca), C(24), C(0d), C(69), C(a3), C(3a), C(42),
             C(ad), C(2e), C(96), C(5e), C(85), C(62), C(8b), C(eb),
             C(ae), C(ba), C(52), C(3e), C(9f), C(35), C(73), C(e9),
             C(5f), C(a9), C(4b), C(5a), C(5a), C(2e), C(fb), C(52),
             C(eb), C(c1), C(bf), C(83), C(df), C(29), C(8f), C(e8),
             C(10), C(30), C(77), C(a0), C(b4), C(4c), C(1d), C(e1),
             C(48)}
        }
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(Parser::decrypt_aes256_cbc_plain(i.second, ENCRYPTION_KEY), i.first);
}

BOOST_AUTO_TEST_CASE(Parser_decrypt_aes256_cbc_base64)
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

BOOST_AUTO_TEST_CASE(crypto_pbkdf2_sha256_short)
{
    std::string expected {C(12), C(0f), C(b6), C(cf), C(fc), C(f8), C(b3), C(2c),
                          C(43), C(e7), C(22), C(52), C(56), C(c4), C(f8), C(37),
                          C(a8), C(65), C(48), C(c9), C(2c), C(cc), C(35), C(48),
                          C(08), C(05), C(98), C(7c), C(b7), C(0b), C(e1), C(7b)};
    auto actual = pbkdf2_sha256("password", "salt", 1, expected.size());

    BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(crypto_pbkdf2_sha256_long)
{
    std::string expected {C(34), C(8c), C(89), C(db), C(cb), C(d3), C(2b), C(2f),
                          C(32), C(d8), C(14), C(b8), C(11), C(6e), C(84), C(cf),
                          C(2b), C(17), C(34), C(7e), C(bc), C(18), C(00), C(18),
                          C(1c), C(4e), C(2a), C(1f), C(b8), C(dd), C(53), C(e1),
                          C(c6), C(35), C(51), C(8c), C(7d), C(ac), C(47), C(e9)};
    auto actual = pbkdf2_sha256("passwordPASSWORDpassword",
                                "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                                4096,
                                expected.size());

    BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(crypto_sha256)
{
    std::map<std::string, std::string> const test_cases = {
        {
            "abc",
            {C(ba), C(78), C(16), C(bf), C(8f), C(01), C(cf), C(ea),
             C(41), C(41), C(40), C(de), C(5d), C(ae), C(22), C(23),
             C(b0), C(03), C(61), C(a3), C(96), C(17), C(7a), C(9c),
             C(b4), C(10), C(ff), C(61), C(f2), C(00), C(15), C(ad)}
        },
        {
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            {C(24), C(8d), C(6a), C(61), C(d2), C(06), C(38), C(b8),
             C(e5), C(c0), C(26), C(93), C(0c), C(3e), C(60), C(39),
             C(a3), C(3c), C(e4), C(59), C(64), C(ff), C(21), C(67),
             C(f6), C(ec), C(ed), C(d4), C(19), C(db), C(06), C(c1)}
        },
    };

    for (auto const &i: test_cases)
        BOOST_CHECK(sha256(i.first) == i.second);
}

BOOST_AUTO_TEST_CASE(crypto_decrypt_aes256_ecb)
{
    std::map<std::string, std::string> const test_cases {
        {"", ""},
        {"0123456789", {C(f2), C(61), C(f1), C(20), C(0f), C(2b), C(ba), C(5e),
                        C(9e), C(ab), C(bd), C(9a), C(fc), C(6a), C(b6), C(8b)}},
        {"All your base are belong to us", {C(04), C(d8), C(5d), C(dd), C(0d), C(d9), C(54), C(e0),
                                            C(f1), C(93), C(d7), C(34), C(0b), C(bf), C(3c), C(35),
                                            C(43), C(d3), C(21), C(f6), C(27), C(66), C(ec), C(57),
                                            C(7e), C(48), C(21), C(b4), C(c2), C(7c), C(8d), C(53)}}
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(decrypt_aes256(i.second, ENCRYPTION_KEY, CipherMode::ECB, {}), i.first);
}

BOOST_AUTO_TEST_CASE(crypto_decrypt_aes256_cbc)
{
    std::map<std::string, std::pair<std::string, std::string>> const test_cases {
        {"", {"", ""}},
        {
            "0123456789",
            {
                {C(0f), C(a1), C(88), C(8c), C(b4), C(bc), C(61), C(b8),
                 C(b2), C(bb), C(07), C(99), C(70), C(a1), C(7b), C(77)},
                {C(a1), C(59), C(cf), C(eb), C(60), C(f9), C(df), C(8b),
                 C(2a), C(8e), C(1b), C(c8), C(7b), C(f0), C(37), C(57)}
            }
        },
        {
            "All your base are belong to us",
            {
                {C(ca), C(24), C(0d), C(69), C(a3), C(3a), C(42), C(ad),
                 C(2e), C(96), C(5e), C(85), C(62), C(8b), C(eb), C(ae)},
                {C(ba), C(52), C(3e), C(9f), C(35), C(73), C(e9), C(5f),
                 C(a9), C(4b), C(5a), C(5a), C(2e), C(fb), C(52), C(eb),
                 C(c1), C(bf), C(83), C(df), C(29), C(8f), C(e8), C(10),
                 C(30), C(77), C(a0), C(b4), C(4c), C(1d), C(e1), C(48)}
            }
        },
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(decrypt_aes256(i.second.second, ENCRYPTION_KEY, CipherMode::CBC, i.second.first),
                          i.first);
}

BOOST_AUTO_TEST_CASE(utils_to_hex)
{
    std::map<std::string, std::string> const test_cases = {
        {"", {}},
        {"00", {C(00)}},
        {"00ff", {C(00), C(ff)}},
        {"00010203040506070809", {C(00), C(01), C(02), C(03), C(04), C(05), C(06), C(07), C(08), C(09)}},
        {"000102030405060708090a0b0c0d0e0f", {C(00), C(01), C(02), C(03), C(04), C(05), C(06), C(07),
                                              C(08), C(09), C(0a), C(0b), C(0c), C(0d), C(0e), C(0f)}},
        {"8af633933e96a3c3550c2734bd814195", {C(8a), C(f6), C(33), C(93), C(3e), C(96), C(a3), C(c3),
                                              C(55), C(0c), C(27), C(34), C(bd), C(81), C(41), C(95)}},
    };

    for (auto const &i: test_cases)
        BOOST_CHECK_EQUAL(to_hex(i.second), i.first);
}

BOOST_AUTO_TEST_CASE(utils_decode_base64)
{
    BOOST_CHECK(decode_base64("") == "");
    BOOST_CHECK(decode_base64("YQ==") == std::string{C(61)});
    BOOST_CHECK(decode_base64("YWI=") == (std::string{C(61), C(62)}));
    BOOST_CHECK(decode_base64("YWJj") == (std::string{C(61), C(62), C(63)}));
    BOOST_CHECK(decode_base64("YWJjZA==") == (std::string{C(61), C(62), C(63), C(64)}));
}
