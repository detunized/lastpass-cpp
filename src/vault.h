#pragma once

#include "account.h"
#include "blob.h"

#include <string>
#include <vector>

namespace lastpass
{

class Vault
{
public:
    typedef std::vector<Account> Accounts;

    static Vault create(std::string const &username, std::string const &password);
    static Vault create(Blob const &blob, std::string const &username, std::string const &password);
    static Vault create(Blob const &blob, std::string const &encryption_key);

    static Blob download(std::string const &username, std::string const &password);

    Accounts const &accounts() const
    {
        return accounts_;
    }

private:
    Vault(Accounts &&accounts):
        accounts_(accounts)
    {
    }

    Accounts accounts_;
};

}