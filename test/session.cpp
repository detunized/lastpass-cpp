#include "test.h"

namespace
{

using namespace lastpass;
using namespace test;

auto const SESSION_ID = "53ru,Hb713QnEVM5zWZ16jMvxS0"_s;
int const KEY_ITERATION_COUNT = 5000;

Session session()
{
    return {SESSION_ID, KEY_ITERATION_COUNT};
}

BOOST_AUTO_TEST_CASE(Session_id_returns_id)
{
    BOOST_CHECK_EQUAL(session().id(), SESSION_ID);
}

BOOST_AUTO_TEST_CASE(Session_key_iteration_count_returns_key_iteration_count)
{
    BOOST_CHECK_EQUAL(session().key_iteration_count(), KEY_ITERATION_COUNT);
}

}