#pragma once

#include <map>
#include <string>

namespace lastpass
{

class WebClient
{
public:
    typedef std::map<std::string, std::string> Values;

    virtual ~WebClient() {}

    virtual std::string get(std::string const &url, Values const &values) = 0;
    virtual std::string post(std::string const &url, Values const &values) = 0;
};

}
