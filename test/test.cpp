// TODO: Split this module into separate files!

#include "testdata.h"

#include "../src/account.h"
#include "../src/crypto.h"
#include "../src/fetcher.h"
#include "../src/parser.h"
#include "../src/session.h"
#include "../src/vault.h"
#include "../src/utils.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE lastpass
#include <boost/test/unit_test.hpp>

#define C(dd) (static_cast<char>(0x##dd))

using namespace lastpass;

namespace
{

int const KEY_ITERATION_COUNT = 5000;
std::string const BLOB_BYTES {C(4c), C(50), C(41), C(56), C(00), C(00), C(00), C(03), C(31), C(31), C(38)};
std::string const ENCRYPTION_KEY {C(39), C(f3), C(94), C(bd), C(59), C(d0), C(cc), C(1e),
                                  C(2f), C(e3), C(db), C(0d), C(87), C(8f), C(8f), C(77),
                                  C(02), C(05), C(6f), C(d1), C(6b), C(e7), C(e8), C(d5),
                                  C(7d), C(64), C(53), C(7f), C(e1), C(36), C(1a), C(18)};

void check_equal(Account const &account, test::Account const &expected)
{
    BOOST_CHECK_EQUAL(account.id(), expected.id);
    BOOST_CHECK_EQUAL(account.name(), expected.name);
    BOOST_CHECK_EQUAL(account.username(), expected.username);
    BOOST_CHECK_EQUAL(account.password(), expected.password);
    BOOST_CHECK_EQUAL(account.url(), expected.url);
    BOOST_CHECK_EQUAL(account.group(), expected.group);
}

}

BOOST_AUTO_TEST_CASE(Parser_extract_chunks)
{
    std::istringstream s(std::string(std::begin(BLOB_BYTES), std::end(BLOB_BYTES)));
    BOOST_CHECK(Parser::extract_chunks(s) == (Chunks {{ChunkId::LPAV, {{C(31), C(31), C(38)}}}}));
}

BOOST_AUTO_TEST_CASE(Parser_extract_chunks_with_filter)
{
    std::istringstream s(std::string(std::begin(BLOB_BYTES), std::end(BLOB_BYTES)));
    BOOST_CHECK(Parser::extract_chunks(s, {ChunkId::LPAV}) == (Chunks {{ChunkId::LPAV, {{C(31), C(31), C(38)}}}}));
}

BOOST_AUTO_TEST_CASE(Parser_extract_chunks_accounts)
{
    std::istringstream s(test::BLOB);
    auto chunks = Parser::extract_chunks(s, {ChunkId::ACCT});
    BOOST_CHECK_EQUAL(chunks.size(), 1);
    BOOST_CHECK_EQUAL(chunks[ChunkId::ACCT].size(), test::ACCOUNTS.size());

    auto const &accounts = chunks[ChunkId::ACCT];
    for (size_t i = 0, size = accounts.size(); i < size; ++i)
        check_equal(Parser::parse_account(accounts[i], test::ENCRYPTION_KEY), test::ACCOUNTS[i]);
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

BOOST_AUTO_TEST_CASE(Vault_create_from_blob)
{
    auto vault = Vault::create(Blob(test::BLOB, KEY_ITERATION_COUNT), test::ENCRYPTION_KEY);
    auto const &accounts = vault.accounts();

    BOOST_CHECK_EQUAL(accounts.size(), test::ACCOUNTS.size());
    for (size_t i = 0, size = accounts.size(); i < size; ++i)
        check_equal(accounts[i], test::ACCOUNTS[i]);
}
