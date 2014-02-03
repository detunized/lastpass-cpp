#pragma once

#include <string>

namespace lastpass
{

class Account
{
public:
    static Account parse(std::string const &bytes);

    Account(std::string &&id,
            std::string &&name,
            std::string &&username,
            std::string &&password,
            std::string &&url,
            std::string &&group):
        id_(id),
        name_(name),
        username_(username),
        password_(password),
        url_(url),
        group_(group)
    {
    }

    std::string const &id() const
    {
        return id_;
    }

    std::string const &name() const
    {
        return name_;
    }

    std::string const &username() const
    {
        return username_;
    }

    std::string const &password() const
    {
        return password_;
    }

    std::string const &url() const
    {
        return url_;
    }

    std::string const &group() const
    {
        return group_;
    }

private:
    std::string id_;
    std::string name_;
    std::string username_;
    std::string password_;
    std::string url_;
    std::string group_;
};

}