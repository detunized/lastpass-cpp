#include "fetcher.h"
#include "crypto.h"
#include "utils.h"
#include "xml.h"

namespace lastpass
{

Session Fetcher::login(std::string const &username, std::string const &password, WebClient &web_client)
{
    return login(username, password, request_iteration_count(username, web_client), web_client);
}

Session Fetcher::login(std::string const &username, std::string const &password, int iteration_count, WebClient &web_client)
{
    auto response = web_client.post("https://lastpass.com/login.php", {
        {"method", "mobile"},
        {"web", "1"},
        {"xml", "1"},
        {"username", username},
        {"hash", make_hash(username, password, iteration_count)},
        {"iterations", std::to_string(iteration_count)}
    });
    Xml xml(response);
    auto id = xml.get_attribute("//ok/@sessionid");

    if (id.empty())
        throw std::runtime_error("Failed to login");

    // TODO: Handle errors here!

    return {id, iteration_count};
}

Blob Fetcher::fetch(Session const &session, WebClient &web_client)
{
    auto response = web_client.get("https://lastpass.com/getaccts.php",
                                   {{"mobile", "1"}, {"b64", "1"}, {"hash", "0.0"}},
                                   {{"PHPSESSID", session.id()}});

    return {decode_base64(response), session.key_iteration_count()};
}

int Fetcher::request_iteration_count(std::string const &username, WebClient &web_client)
{
    return std::stoi(web_client.post("https://lastpass.com/iterations.php", {{"email", username}}));
}

std::string Fetcher::make_key(std::string const &username, std::string const &password, int iteration_count)
{
    return iteration_count == 1
        ? sha256(username + password)
        : pbkdf2_sha256(password, username, iteration_count, 32);
}

std::string Fetcher::make_hash(std::string const &username, std::string const &password, int iteration_count)
{
    auto key = make_key(username, password, iteration_count);
    return iteration_count == 1
        ? to_hex(sha256(to_hex(key) + password))
        : to_hex(pbkdf2_sha256(key, password, 1, 32));
}

}
