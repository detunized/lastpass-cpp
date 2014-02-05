#include "account.h"
#include "parser.h"

#include <sstream>

namespace lastpass
{

Account Account::parse(std::string const &bytes)
{
    std::istringstream s(bytes); // TODO: Get rid of the copy!

    auto id = Parser::read_item(s);
    auto name = Parser::read_item(s);
    auto group = Parser::read_item(s);
    auto url = Parser::read_item(s);
    Parser::skip_item(s);
    Parser::skip_item(s);
    Parser::skip_item(s);
    auto username = Parser::read_item(s);
    auto password = Parser::read_item(s);

    return {std::move(id),
            std::move(name),
            std::move(username),
            std::move(password),
            std::move(url),
            std::move(group)};
}

}
