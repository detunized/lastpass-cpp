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
