#pragma once

#include "webclient.h"
#include <string>

namespace lastpass
{

class Fetcher
{
public:
    static int request_iteration_count(std::string const &username, WebClient &web_client);
};

}
