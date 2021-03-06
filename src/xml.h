// Copyright (C) 2014 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#pragma once

#include <memory>
#include <string>

namespace lastpass
{

class Xml
{
public:
    explicit Xml(std::string const &text);
    ~Xml();

    std::string get_attribute(std::string const &xpath) const;

private:
    struct PrivateData;
    std::unique_ptr<PrivateData> d;
};

}
