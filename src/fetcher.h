#pragma once

#include "webclient.h"
#include "session.h"
#include "blob.h"

#include <string>
#include <vector>

namespace lastpass
{

class Fetcher
{
public:
    static Session login(std::string const &username, std::string const &password, WebClient &web_client);
    static Session login(std::string const &username, std::string const &password, int iteration_count, WebClient &web_client);
    static Blob fetch(Session const &session, WebClient &web_client);

    static int request_iteration_count(std::string const &username, WebClient &web_client);
    static std::vector<uint8_t> make_key(std::string const &username, std::string const &password, int iteration_count);
    static std::string make_hash(std::string const &username, std::string const &password, int iteration_count);
    static std::vector<uint8_t> pbkdf2_sha256(std::vector<uint8_t> const &password,
                                              std::vector<uint8_t> const &salt,
                                              int iteration_count,
                                              size_t size);
    static std::vector<uint8_t> sha256(std::string const &text);
};

}
