#pragma once

#include "webclient.h"
#include <string>

namespace lastpass
{

struct Session {};

class Fetcher
{
public:
    static Session login(std::string const &username, std::string const &password, WebClient &web_client);
    static Session login(std::string const &username, std::string const &password, int iteration_count, WebClient &web_client);
    static int request_iteration_count(std::string const &username, WebClient &web_client);
    static std::string make_hash(std::string const &username, std::string const &password, int iteration_count);
};

}
