// TODO: Split this module into separate files!

// This defines main.
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE lastpass
#include <boost/test/unit_test.hpp>

#include "test.h"

namespace lastpass
{

namespace test
{

void check_equal(Account const &account, data::Account const &expected)
{
    BOOST_CHECK_EQUAL(account.id(), expected.id);
    BOOST_CHECK_EQUAL(account.name(), expected.name);
    BOOST_CHECK_EQUAL(account.username(), expected.username);
    BOOST_CHECK_EQUAL(account.password(), expected.password);
    BOOST_CHECK_EQUAL(account.url(), expected.url);
    BOOST_CHECK_EQUAL(account.group(), expected.group);
}

}

}
