#include "../src/curlwebclient.h"
#include "../src/fetcher.h"

#include <iostream>

int main(int argc, char const *argv[])
{
    using namespace lastpass;

    try
    {
        CurlWebClient web_client;
        std::cout << "GET:\n"
                  << web_client.get("http://httpbin.org/get", {{"first name", "Milton"}, {"last name", "Waddams"}})
                  << "\n";
        std::cout << "POST:\n"
                  << web_client.post("http://httpbin.org/post", {{"first name", "bill"}, {"last name", "Lumbergh"}})
                  << "\n";
        std::cout << "iterations:\n"
                  << Fetcher::request_iteration_count("lastpass.ruby@gmail.com", web_client)
                  << "\n";
    }
    catch (std::exception const &e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
