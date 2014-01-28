#pragma once

#include "webclient.h"

namespace lastpass
{

class CurlWebClient: public WebClient
{
public:
    virtual std::string get(std::string const &url, Values const &values) override;
    virtual std::string post(std::string const &url, Values const &values) override;
};

}
