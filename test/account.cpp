#include "test.h"

namespace
{

using namespace lastpass;
using namespace test;

auto const ID = "id"_s;
auto const NAME = "name"_s;
auto const USERNAME = "username"_s;
auto const PASSWORD = "password"_s;
auto const URL = "url"_s;
auto const GROUP = "group"_s;

Account account()
{
    return {std::string(ID),
            std::string(NAME),
            std::string(USERNAME),
            std::string(PASSWORD),
            std::string(URL),
            std::string(GROUP)};
}

BOOST_AUTO_TEST_CASE(Account_id_returns_id)
{
    BOOST_CHECK_EQUAL(account().id(), ID);
}

BOOST_AUTO_TEST_CASE(Account_name_returns_name)
{
    BOOST_CHECK_EQUAL(account().name(), NAME);
}

BOOST_AUTO_TEST_CASE(Account_username_returns_username)
{
    BOOST_CHECK_EQUAL(account().username(), USERNAME);
}

BOOST_AUTO_TEST_CASE(Account_password_returns_password)
{
    BOOST_CHECK_EQUAL(account().password(), PASSWORD);
}

BOOST_AUTO_TEST_CASE(Account_url_returns_url)
{
    BOOST_CHECK_EQUAL(account().url(), URL);
}

BOOST_AUTO_TEST_CASE(Account_group_returns_group)
{
    BOOST_CHECK_EQUAL(account().group(), GROUP);
}

}
