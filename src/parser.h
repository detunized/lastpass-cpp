#pragma once

#include "utils.h"

#include <istream>
#include <map>
#include <string>

namespace lastpass
{

typedef std::map<std::string, Bytes> Chunks;

class Parser
{
public:
    static Chunks extract_chunks(std::istream &stream);
};

}
