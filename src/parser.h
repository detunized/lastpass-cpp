#pragma once

#include "utils.h"

#include <istream>
#include <map>
#include <string>

namespace lastpass
{

typedef uint32_t ChunkId;
typedef std::map<ChunkId, std::vector<Bytes>> Chunks;

class Parser
{
public:
    static Chunks extract_chunks(std::istream &stream);
    static std::pair<ChunkId, Bytes> read_chunk(std::istream &stream);
    static ChunkId read_id(std::istream &stream);
    static size_t read_size(std::istream &stream);
    static Bytes read_payload(std::istream &stream, size_t size);
};

}
