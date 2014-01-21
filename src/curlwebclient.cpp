#include "curlwebclient.h"

#include <curl/curl.h>

namespace lastpass
{

namespace
{

class CurlGlobalInitializer
{
public:
    CurlGlobalInitializer()
    {
        curl_global_init(CURL_GLOBAL_ALL);
    }

    ~CurlGlobalInitializer()
    {
        curl_global_cleanup();
    }
} curl_global_initializer;

class Curl
{
public:
    Curl(): curl_(curl_easy_init())
    {
        if (curl_ == nullptr)
            throw std::runtime_error("Failed to initialize cURL");
    }

    ~Curl()
    {
        curl_easy_cleanup(curl_);
    }

    operator CURL *() const
    {
        return curl_;
    }

private:
    CURL *curl_;

    // No copies
    Curl(Curl const &) = delete;
    Curl &operator =(Curl const &) = delete;
};

}

std::string CurlWebClient::get(std::string const &url, std::map<std::string, std::string> const &values)
{
    return {};
}

std::string CurlWebClient::post(std::string const &url, std::map<std::string, std::string> const &values)
{
    return {};
}

}
