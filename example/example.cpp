#include "../src/curlwebclient.h"

#include <iostream>

int main(int argc, char const *argv[])
{
    try
    {
        lastpass::CurlWebClient web_client;
        std::cout << web_client.get("http://httpbin.org/get", {{}})
                  << std::endl;
    }
    catch (std::exception const &e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
