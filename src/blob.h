#pragma once

#include <vector>

namespace lastpass
{

class Blob
{
public:
    Blob(std::vector<uint8_t> const &bytes, int key_iteration_count):
        bytes_(bytes),
        key_iteration_count_(key_iteration_count)
    {
    }

    std::vector<uint8_t> const &bytes() const
    {
        return bytes_;
    }

    int key_iteration_count() const
    {
        return key_iteration_count_;
    }

private:
    std::vector<uint8_t> bytes_;
    int key_iteration_count_;
};

}
