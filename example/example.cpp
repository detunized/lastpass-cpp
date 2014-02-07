#include "../src/vault.h"

#include <fstream>
#include <iostream>

namespace
{

// Copy example/credentials.txt.example to example/credentials.txt and
// put your username and then password on the next line.

std::pair<std::string, std::string> read_credentials()
{
    std::string username;
    std::string password;

    std::ifstream f("example/credentials.txt");
    if (f.is_open())
    {
        f >> username >> password;
    }
    else
    {
        std::cout << "Enter username: " << std::flush;
        std::cin >> username;

        std::cout << "Enter password: " << std::flush;
        std::cin >> password;
    }

    return std::make_pair(username, password);
}

}

int main(int argc, char const *argv[])
{
    using namespace lastpass;

    try
    {
        auto credentials = read_credentials();

        auto vault = Vault::create(credentials.first, credentials.second);
        for (auto const &i: vault.accounts())
        {
            std::cout << "      id: " << i.id() << '\n'
                      << "    name: " << i.name() << '\n'
                      << "username: " << i.username() << '\n'
                      << "password: " << i.password() << '\n'
                      << "   group: " << i.group() << '\n'
                      << "     url: " << i.url() << '\n'
                      << '\n';
        }
    }
    catch (std::exception const &e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
