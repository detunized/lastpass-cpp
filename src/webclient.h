#pragma once

#include <map>
#include <string>

namespace lastpass
{

class WebClient
{
public:
    virtual ~WebClient() {}

    virtual std::string get(std::string const &url, std::map<std::string, std::string> const &values) = 0;
    virtual std::string post(std::string const &url, std::map<std::string, std::string> const &values) = 0;
};

}
