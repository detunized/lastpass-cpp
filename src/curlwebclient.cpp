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
