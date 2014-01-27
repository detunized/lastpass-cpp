#include "fetcher.h"

#include <CommonCrypto/CommonDigest.h>

namespace lastpass
{

Session Fetcher::login(std::string const &username, std::string const &password, WebClient &web_client)
{
    auto const iteration_count = request_iteration_count(username, web_client);
    auto response = login(username, password, iteration_count, web_client);

    return {};
}

Session Fetcher::login(std::string const &username, std::string const &password, int iteration_count, WebClient &web_client)
{
    auto const response = web_client.post("https://lastpass.com/login.php", {
        {"method", "mobile"},
        {"web", "1"},
        {"xml", "1"},
        {"username", username},
        {"hash", make_hash(username, password, iteration_count)},
        {"iterations", std::to_string(iteration_count)}
    });

    return {};
}

int Fetcher::request_iteration_count(std::string const &username, WebClient &web_client)
{
    return std::stoi(web_client.post("https://lastpass.com/iterations.php", {{"email", username}}));
}

std::string Fetcher::make_hash(std::string const &username, std::string const &password, int iteration_count)
{
    return "a1943cfbb75e37b129bbf78b9baeab4ae6dd08225776397f66b8e0c7a913a055";
}

std::vector<uint8_t> Fetcher::sha256(std::string const &text)
{
    std::vector<uint8_t> hash(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256(text.c_str(), text.size(), &hash[0]);
    return hash;
}

}
