// Copyright (C) 2014 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#pragma once

#include <string>

namespace lastpass
{

class Session
{
public:
    Session(std::string const &id, int key_iteration_count):
        id_(id),
        key_iteration_count_(key_iteration_count)
    {
    }

    std::string const &id() const
    {
        return id_;
    }

    int key_iteration_count() const
    {
        return key_iteration_count_;
    }

private:
    std::string const id_;
    int const key_iteration_count_;
};

}
