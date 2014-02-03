#include "fetcher.h"
#include "utils.h"

// TODO: Make a crypto interface and remove ifdefs!
#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/sha.h>
#else
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#endif

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <memory>
#include <stdexcept>

namespace lastpass
{

namespace
{

class Xml
{
public:
    explicit Xml(std::string const &text): document_(nullptr)
    {
        document_ = xmlReadMemory(text.c_str(), text.size(), "", nullptr, 0);
        if (document_ == nullptr)
            throw std::runtime_error("Failed to parse XML");
    }

    ~Xml()
    {
        xmlFreeDoc(document_);
    }

    std::string get_attribute(std::string const &xpath) const
    {
        std::unique_ptr<xmlXPathContext, decltype(&xmlXPathFreeContext)>context(
            xmlXPathNewContext(document_),
            &xmlXPathFreeContext);
        if (context.get() == nullptr)
            return "";

        std::unique_ptr<xmlXPathObject, decltype(&xmlXPathFreeObject)>result(
            xmlXPathEvalExpression(reinterpret_cast<xmlChar const *>(xpath.c_str()), context.get()),
            &xmlXPathFreeObject);
        if (result.get() == nullptr)
            return "";

        xmlNodeSet const *nodes = result->nodesetval;
        if (nodes == nullptr ||
            nodes->nodeNr <= 0 ||
            nodes->nodeTab[0]->type != XML_ATTRIBUTE_NODE)
            return "";

        return reinterpret_cast<char const *>(((xmlAttrPtr)nodes->nodeTab[0])->children->content);
    }

private:
    xmlDocPtr document_;
};

}

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

    return {to_bytes(response), session.key_iteration_count()};
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

#ifdef USE_OPENSSL
    PKCS5_PBKDF2_HMAC(reinterpret_cast<char const *>(password.data()),
                      password.size(),
                      salt.data(),
                      salt.size(),
                      iteration_count,
                      EVP_sha256(),
                      size,
                      &key[0]);
#else
    CCKeyDerivationPBKDF(kCCPBKDF2,
                         reinterpret_cast<char const *>(password.data()),
                         password.size(),
                         salt.data(),
                         salt.size(),
                         kCCPRFHmacAlgSHA256,
                         iteration_count,
                         &key[0],
                         size);
#endif

    return key;
}

std::vector<uint8_t> Fetcher::sha256(std::string const &text)
{
#ifdef USE_OPENSSL
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, text.c_str(), text.size());
    SHA256_Final(&hash[0], &sha256);
#else
    std::vector<uint8_t> hash(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256(text.c_str(), text.size(), &hash[0]);
#endif

    return hash;
}

}
