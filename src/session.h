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
