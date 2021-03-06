// Copyright (C) 2014 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#pragma once

#include "../src/parser.h"

namespace lastpass
{

namespace test
{

namespace data
{

struct Account
{
    Account(std::string &&id,
            std::string &&name,
            std::string &&username,
            std::string &&password,
            std::string &&url,
            std::string &&group):
        id(std::move(id)),
        name(std::move(name)),
        username(std::move(username)),
        password(std::move(password)),
        url(std::move(url)),
        group(std::move(group))
    {
    }

    std::string const id;
    std::string const name;
    std::string const username;
    std::string const password;
    std::string const url;
    std::string const group;
};

extern int const KEY_ITERATION_COUNT;
extern std::string const ENCRYPTION_KEY;
extern std::vector<ChunkId> const CHUNK_IDS;
extern std::vector<Account> const ACCOUNTS;
extern std::string const BLOB;

}

}

}
