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
    explicit Curl(std::string const &url): curl_(curl_easy_init())
    {
        if (curl_ == nullptr)
            throw std::runtime_error("Failed to initialize cURL");

        curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
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

size_t store_response(void *buffer, size_t size, size_t count, std::string *response_out)
{
    auto total = size * count;
    response_out->append((char const *)buffer, total);
    return total;
}

}

std::string CurlWebClient::get(std::string const &url, std::map<std::string, std::string> const &values)
{
    Curl curl(url);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &store_response);

    CURLcode result = curl_easy_perform(curl);
    if (result != CURLE_OK)
        throw std::runtime_error("GET failed");

    return response;
}

std::string CurlWebClient::post(std::string const &url, std::map<std::string, std::string> const &values)
{
    return {};
}

}
