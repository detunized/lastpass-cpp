#pragma once

#include "../src/parser.h"

namespace lastpass
{

namespace test
{

struct Account
{
    Account(std::string &&id,
            std::string &&name,
            std::string &&username,
            std::string &&password,
            std::string &&url,
            std::string &&group):
        id(id),
        name(name),
        username(username),
        password(password),
        url(url),
        group(group)
    {
    }

    std::string const id;
    std::string const name;
    std::string const username;
    std::string const password;
    std::string const url;
    std::string const group;
};

extern std::vector<ChunkId> const CHUNK_IDS;
extern std::string const BLOB_BASE64;
extern std::string const BLOB;
extern std::string const ENCRYPTION_KEY;
extern std::vector<Account> const ACCOUNTS;

}

}
