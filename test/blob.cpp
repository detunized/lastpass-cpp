// Copyright (C) 2014 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#include "test.h"

namespace
{

using namespace lastpass;
using namespace test;

auto const BLOB_BYTES = "\x4c\x50\x41\x56\x00\x00\x00\x03\x31\x31\x38"_s;
int const KEY_ITERATION_COUNT = 5000;

Blob blob()
{
    return {BLOB_BYTES, KEY_ITERATION_COUNT};
}

BOOST_AUTO_TEST_CASE(blob_bytes_returns_set_value)
{
    BOOST_CHECK(blob().bytes() == BLOB_BYTES);
}

BOOST_AUTO_TEST_CASE(blob_key_iteration_count_returns_set_value)
{
    BOOST_CHECK_EQUAL(blob().key_iteration_count(), KEY_ITERATION_COUNT);
}

}
