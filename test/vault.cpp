#include "test.h"
#include "testdata.h"

namespace
{

using namespace lastpass;
using namespace test;

BOOST_AUTO_TEST_CASE(vault_create_creates_vault_from_blob)
{
    auto vault = Vault::create(Blob(data::BLOB, data::KEY_ITERATION_COUNT), data::ENCRYPTION_KEY);
    auto const &accounts = vault.accounts();

    BOOST_CHECK_EQUAL(accounts.size(), data::ACCOUNTS.size());
    for (size_t i = 0, size = accounts.size(); i < size; ++i)
        check_equal(accounts[i], data::ACCOUNTS[i]);
}

}
