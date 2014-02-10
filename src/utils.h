// Copyright (C) 2014 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#pragma once

#include <functional>
#include <string>

namespace lastpass
{

class AtExit
{
public:
    typedef std::function<void()> Function;

    explicit AtExit(Function &&f):
        f_(std::move(f))
    {
    }

    ~AtExit()
    {
        f_();
    }

private:
    Function f_;
};

std::string encode_hex(std::string const &bytes);
std::string decode_hex(std::string const &hex_text);
std::string decode_base64(std::string const &base64_text);

}
