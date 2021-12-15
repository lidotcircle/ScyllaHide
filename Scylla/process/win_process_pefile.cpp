#include "process/win_process_pefile.h"
#include "process/memory_map_pefile.h"
#include <stdexcept>
#include <pe-parse/parse.h>
using namespace std;


WinProcessPEFile::WinProcessPEFile(const string& path): MemoryMapCollection(), pehandle(nullptr, [](peparse::parsed_pe*) {})
{
    auto handle = peparse::ParsePEFromFile(path.c_str());
    if (!handle)
        throw runtime_error("Failed to open PE file");

    this->pehandle = decltype(this->pehandle)(handle, peparse::DestructParsedPE);

    auto sec_iter = [](
            void* N,
            const peparse::VA& secbase,
            const string& secname,
            const peparse::image_section_header& header,
            const peparse::bounded_buffer* data) 
    {
        auto self = static_cast<WinProcessPEFile*>(N);
        auto map = std::make_shared<MemoryMapPEFile>(data, reinterpret_cast<void*>(secbase), header.SizeOfRawData, secname);
        self->mmaps.push_back(map);
        return 0;
    };
    peparse::IterSec(this->pehandle.get(), sec_iter, static_cast<void*>(this));
}

size_t WinProcessPEFile::map_count() const {
    return this->mmaps.size();
}

std::shared_ptr<MemoryMap> WinProcessPEFile::get_map(size_t index) {
    return this->mmaps[index];
}

