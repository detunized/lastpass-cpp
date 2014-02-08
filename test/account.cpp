#include "../src/account.h"

#include <boost/test/unit_test.hpp>

using namespace lastpass;

namespace
{

std::string const ID = "id";
std::string const NAME = "name";
std::string const USERNAME = "username";
std::string const PASSWORD = "password";
std::string const URL = "url";
std::string const GROUP = "group";

Account const ACCOUNT {std::string(ID),
                       std::string(NAME),
                       std::string(USERNAME),
                       std::string(PASSWORD),
                       std::string(URL),
                       std::string(GROUP)};

}

BOOST_AUTO_TEST_CASE(Account_id_returns_id)
{
    BOOST_CHECK_EQUAL(ACCOUNT.id(), ID);
}

BOOST_AUTO_TEST_CASE(Account_name_returns_name)
{
    BOOST_CHECK_EQUAL(ACCOUNT.name(), NAME);
}

BOOST_AUTO_TEST_CASE(Account_username_returns_username)
{
    BOOST_CHECK_EQUAL(ACCOUNT.username(), USERNAME);
}

BOOST_AUTO_TEST_CASE(Account_password_returns_password)
{
    BOOST_CHECK_EQUAL(ACCOUNT.password(), PASSWORD);
}

BOOST_AUTO_TEST_CASE(Account_url_returns_url)
{
    BOOST_CHECK_EQUAL(ACCOUNT.url(), URL);
}

BOOST_AUTO_TEST_CASE(Account_group_returns_group)
{
    BOOST_CHECK_EQUAL(ACCOUNT.group(), GROUP);
}
