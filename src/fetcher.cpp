#include "fetcher.h"

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonKeyDerivation.h>

namespace lastpass
{

Session Fetcher::login(std::string const &username, std::string const &password, WebClient &web_client)
{
    return login(username, password, request_iteration_count(username, web_client), web_client);
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

    return {response, iteration_count};
}

int Fetcher::request_iteration_count(std::string const &username, WebClient &web_client)
{
    return std::stoi(web_client.post("https://lastpass.com/iterations.php", {{"email", username}}));
}

std::vector<uint8_t> Fetcher::make_key(std::string const &username, std::string const &password, int iteration_count)
{
    return iteration_count == 1
        ? sha256(username + password)
        : pbkdf2_sha256(to_bytes(password), to_bytes(username), iteration_count, 32);
}

std::string Fetcher::make_hash(std::string const &username, std::string const &password, int iteration_count)
{
    auto key = make_key(username, password, iteration_count);
    return iteration_count == 1
        ? to_hex(sha256(to_hex(key) + password))
        : to_hex(pbkdf2_sha256(key, to_bytes(password), 1, 32));
}

std::vector<uint8_t> Fetcher::pbkdf2_sha256(std::vector<uint8_t> const &password,
                                            std::vector<uint8_t> const &salt,
                                            int iteration_count,
                                            size_t size)
{
    static_assert(sizeof(uint8_t) == sizeof(char), "uint8_t should be the same size as char");

    std::vector<uint8_t> key(size);
    CCKeyDerivationPBKDF(kCCPBKDF2,
                         reinterpret_cast<char const *>(password.data()),
                         password.size(),
                         salt.data(),
                         salt.size(),
                         kCCPRFHmacAlgSHA256,
                         iteration_count,
                         &key[0],
                         size);
    return key;
}

std::vector<uint8_t> Fetcher::sha256(std::string const &text)
{
    std::vector<uint8_t> hash(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256(text.c_str(), text.size(), &hash[0]);
    return hash;
}

std::vector<uint8_t> Fetcher::to_bytes(std::string const &text)
{
    std::vector<uint8_t> bytes(text.size());
    std::copy(text.begin(), text.end(), bytes.begin());
    return bytes;
}

std::string Fetcher::to_hex(std::vector<uint8_t> const &bytes)
{
    static char const hex_chars[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    std::string hex;
    hex.reserve(bytes.size() * 2);

    for (auto i: bytes)
    {
        hex += hex_chars[i / 16];
        hex += hex_chars[i % 16];
    }

    return hex;
}

}
