// Copyright (C) 2014 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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

    virtual std::string get(std::string const &url,
                            Values const &values = Values(),
                            Values const &cookies = Values()) = 0;
    virtual std::string post(std::string const &url,
                             Values const &values = Values(),
                             Values const &cookies = Values()) = 0;
};

}
