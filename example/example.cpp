#include "../src/vault.h"

#include <iostream>

int main(int argc, char const *argv[])
{
    using namespace lastpass;

    try
    {
        auto vault = Vault::create("username", "password");
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
