// Copyright (C) 2014 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#pragma once

#include "webclient.h"

namespace lastpass
{

class CurlWebClient: public WebClient
{
public:
    virtual std::string get(std::string const &url,
                            Values const &values = Values(),
                            Values const &cookies = Values()) override;
    virtual std::string post(std::string const &url,
                             Values const &values = Values(),
                             Values const &cookies = Values()) override;
};

}
