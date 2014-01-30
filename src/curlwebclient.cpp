#include "curlwebclient.h"

#include <curl/curl.h>

#include <memory>
#include <stdexcept>

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
    explicit Curl(): curl_(curl_easy_init())
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

    std::string url_encode(std::string const &raw)
    {
        std::unique_ptr<char, decltype(&curl_free)> escaped(curl_easy_escape(curl_, raw.c_str(), raw.size()), &curl_free);
        return escaped.get();
    }

    std::string url_encode(std::string const &raw_key, std::string const &raw_value)
    {
        return url_encode(raw_key) + "=" + url_encode(raw_value);
    }

    std::string encode_join(WebClient::Values const &values, std::string const &separator)
    {
        std::string result;
        for (auto const &i: values)
        {
            if (!result.empty())
                result += separator;

            result += url_encode(i.first, i.second);
        }

        return result;
    }

    std::string url_encode(WebClient::Values const &values)
    {
        return encode_join(values, "&");
    }

    std::string cookie_encode(WebClient::Values const &values)
    {
        return encode_join(values, ";");
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

std::string CurlWebClient::get(std::string const &url, Values const &values, Values const &cookies)
{
    Curl curl;

    auto parameters = curl.url_encode(values);
    auto url_with_parameters = parameters.empty() ? url : url + '?' + parameters;
    curl_easy_setopt(curl, CURLOPT_URL, url_with_parameters.c_str());

    // Need to store in a variable to make it stick around until after we're done with the request.
    auto cookie_string = curl.cookie_encode(cookies);
    if (!cookie_string.empty())
        curl_easy_setopt(curl, CURLOPT_COOKIE, cookie_string.c_str());

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &store_response);

    CURLcode result = curl_easy_perform(curl);
    if (result != CURLE_OK)
        throw std::runtime_error("GET failed");

    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200)
        throw std::runtime_error("GET failed");

    return response;
}

std::string CurlWebClient::post(std::string const &url, Values const &values, Values const &cookies)
{
    Curl curl;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // Need to store in a variable to make it stick around until after we're done with the request.
    std::string parameters = curl.url_encode(values);
    curl_easy_setopt(curl, CURLOPT_POST, 1l);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, parameters.c_str());

    // Need to store in a variable to make it stick around until after we're done with the request.
    auto cookie_string = curl.cookie_encode(cookies);
    if (!cookie_string.empty())
        curl_easy_setopt(curl, CURLOPT_COOKIE, cookie_string.c_str());

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &store_response);

    CURLcode result = curl_easy_perform(curl);
    if (result != CURLE_OK)
        throw std::runtime_error("POST failed");

    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200)
        throw std::runtime_error("POST failed");

    return response;
}

}
