// Copyright (C) 2014 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#include "vault.h"
#include "fetcher.h"
#include "parser.h"
#include "curlwebclient.h"

#include <sstream>

namespace lastpass
{

Vault Vault::create(std::string const &username, std::string const &password)
{
    return create(download(username, password), username, password);
}

Vault Vault::create(Blob const &blob, std::string const &username, std::string const &password)
{
    return create(blob, Fetcher::make_key(username, password, blob.key_iteration_count()));
}

Vault Vault::create(Blob const &blob, std::string const &encryption_key)
{
    std::istringstream stream(blob.bytes());
    auto const &chunks = Parser::extract_chunks(stream, {ChunkId::ACCT});
    auto const &account_chunks = chunks.at(ChunkId::ACCT);

    Accounts accounts;
    accounts.reserve(account_chunks.size());

    for (auto const &i: account_chunks)
        accounts.push_back(Parser::parse_account(i, encryption_key));

    return {std::move(accounts)};
}

Blob Vault::download(std::string const &username, std::string const &password)
{
    CurlWebClient web_client;
    return Fetcher::fetch(Fetcher::login(username, password, web_client), web_client);
}

}
