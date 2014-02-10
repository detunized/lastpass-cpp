// Copyright (C) 2014 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#include "test.h"
#include <boost/format.hpp>

namespace
{

using namespace lastpass;
using namespace test;

auto const USERNAME = "username"_s;
auto const PASSWORD = "password"_s;
auto const SESSION_ID = "53ru,Hb713QnEVM5zWZ16jMvxS0"_s;
int const KEY_ITERATION_COUNT = 5000;
auto const HASH = "7880a04588cfab954aa1a2da98fd9c0d2c6eba4c53e36a94510e6dbf30759256"_s;
auto const BLOB = "TFBBVgAAAAMxMTg="_s;
auto const BLOB_BYTES = "\x4c\x50\x41\x56\x00\x00\x00\x03\x31\x31\x38"_s;
auto const LOGIN_URL = "https://lastpass.com/login.php"_s;
auto const ITERATIONS_URL = "https://lastpass.com/iterations.php"_s;
auto const ACCOUNT_DOWNLOAD_URL = "https://lastpass.com/getaccts.php"_s;

class MockWebClient: public WebClient
{
protected:
    MockWebClient(std::string const &url,
                  Values const &values,
                  Values const &cookies,
                  std::string const &response):
        url_(url),
        values_(values),
        cookies_(cookies),
        response_(response)
    {
    }

    std::string fail(std::string const &url, Values const &values, Values const &cookies)
    {
        BOOST_FAIL("Should not be called");
        return {};
    }

    std::string check(std::string const &url, Values const &values, Values const &cookies)
    {
        BOOST_CHECK_EQUAL(url, url_);
        BOOST_CHECK(values == values_);
        BOOST_CHECK(cookies == cookies_);
        return response_;
    }

private:
    std::string url_;
    Values values_;
    Values cookies_;
    std::string response_;
};

class GetMockWebClient: public MockWebClient
{
public:
    GetMockWebClient(std::string const &url,
                     Values const &values,
                     Values const &cookies,
                     std::string const &response):
        MockWebClient(url, values, cookies, response)
    {
    }

    virtual std::string get(std::string const &url,
                        Values const &values,
                        Values const &cookies) override
    {
        return check(url, values, cookies);
    }

    virtual std::string post(std::string const &url,
                             Values const &values,
                             Values const &cookies) override
    {
        return fail(url, values, cookies);
    }
};

class PostMockWebClient: public MockWebClient
{
public:
    PostMockWebClient(std::string const &url,
                      Values const &values,
                      Values const &cookies,
                      std::string const &response):
        MockWebClient(url, values, cookies, response)
    {
    }

    virtual std::string get(std::string const &url,
                            Values const &values,
                            Values const &cookies) override
    {
        return fail(url, values, cookies);
    }

    virtual std::string post(std::string const &url,
                             Values const &values,
                             Values const &cookies) override
    {
        return check(url, values, cookies);
    }
};

BOOST_AUTO_TEST_CASE(fetcher_login_with_iterations)
{
    PostMockWebClient mwc(
        LOGIN_URL,
        {
            {"method", "mobile"},
            {"web", "1"},
            {"xml", "1"},
            {"username", USERNAME},
            {"hash", HASH},
            {"iterations", std::to_string(KEY_ITERATION_COUNT)}
        },
        WebClient::Values(),
        str(boost::format("<ok sessionid=\"%1%\" />") % SESSION_ID)
    );

    auto session = Fetcher::login(USERNAME, PASSWORD, KEY_ITERATION_COUNT, mwc);
    BOOST_CHECK_EQUAL(session.id(), SESSION_ID);
    BOOST_CHECK_EQUAL(session.key_iteration_count(), KEY_ITERATION_COUNT);
}

BOOST_AUTO_TEST_CASE(fetcher_fetch)
{
    GetMockWebClient mwc(
        ACCOUNT_DOWNLOAD_URL,
        {{"mobile", "1"}, {"b64", "1"}, {"hash", "0.0"}},
        {{"PHPSESSID", SESSION_ID}},
        BLOB
    );

    auto blob = Fetcher::fetch(Session(SESSION_ID, KEY_ITERATION_COUNT), mwc);
    BOOST_CHECK(blob.bytes() == BLOB_BYTES);
    BOOST_CHECK_EQUAL(blob.key_iteration_count(), KEY_ITERATION_COUNT);
}

BOOST_AUTO_TEST_CASE(fetcher_request_iteration_count)
{
    PostMockWebClient mwc(
        ITERATIONS_URL,
        {{"email", USERNAME}},
        WebClient::Values(),
        std::to_string(KEY_ITERATION_COUNT)
    );

    BOOST_CHECK_EQUAL(Fetcher::request_iteration_count(USERNAME, mwc), KEY_ITERATION_COUNT);
}

BOOST_AUTO_TEST_CASE(fetcher_make_key)
{
    std::map<int, std::string> test_cases = {
        {1,   "\x0b\xf0\x61\xd9\x21\x96\xc4\x8f\x09\x0e\xee\x78\x0d\xb6\xe9\x57"
              "\xc2\x7d\xc1\xae\xa9\x29\xb7\xac\x21\xbf\x4c\x01\x79\x1e\x17\x76"_s},
        {5,   "\xa4\x4f\x60\xa1\xac\xd2\x09\x1a\xa7\x5b\x07\x22\xc5\x63\x38\x34"
              "\x72\x63\x58\xcb\xc1\xe5\x3d\x79\x74\xc8\x5e\xea\xe8\x35\xa5\x98"_s},
        {50,  "\x1b\x02\x3c\xfe\x43\x72\xd4\xd8\xc8\x7d\xed\xd9\xd1\x50\x19\x7c"
              "\x5e\xfc\xf7\x7f\x14\x56\xe0\xa2\xeb\x10\x0b\xdc\xc2\x41\xbb\x1d"_s},
        {500, "\x39\xf3\x94\xbd\x59\xd0\xcc\x1e\x2f\xe3\xdb\x0d\x87\x8f\x8f\x77"
              "\x02\x05\x6f\xd1\x6b\xe7\xe8\xd5\x7d\x64\x53\x7f\xe1\x36\x1a\x18"_s},
    };

    for (auto const &i: test_cases)
        BOOST_CHECK(Fetcher::make_key("postlass@gmail.com", "pl1234567890", i.first) == i.second);
}

BOOST_AUTO_TEST_CASE(fetcher_make_hash)
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

}
