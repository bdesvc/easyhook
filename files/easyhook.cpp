#include "easyhook.hpp"

/*

Main functions

*/

bool easyhook::install_hook(void* entrypoint, void* inhookproc, void* incallback, TRACED_HOOK_HANDLE out_handle)
{
    auto scanner_object = new scanner("EasyHook.dll");
    auto function_address = (void*)scanner_object->pattern_scan("40 55 56");

    NTSTATUS(*LhInstallHook)(void*, void*, void*, TRACED_HOOK_HANDLE) = nullptr;
    LhInstallHook = reinterpret_cast<decltype(LhInstallHook)>(function_address);

    return LhInstallHook(entrypoint, inhookproc, incallback, out_handle) == 0 ? true : false; // STATUS_SUCCESS
}

bool easyhook::remove_hook(TRACED_HOOK_HANDLE in_handle)
{
    auto scanner_object = new scanner("EasyHook.dll");
    auto function_address = (void*)scanner_object->pattern_scan("40 53 48 83 EC 20 48 8B D9 48 85 C9 0F 84 ? ? ? ? 48 83 F9 FF 0F 84 ? ? ? ? BA ? ? ? ? 48 89 7C 24 ?");

    NTSTATUS(*LhUninstallHook)(TRACED_HOOK_HANDLE) = nullptr;
    LhUninstallHook = reinterpret_cast<decltype(LhUninstallHook)>(function_address);

    return LhUninstallHook(in_handle) == 0 ? true : false; // STATUS_SUCCESS
}

bool easyhook::remove_all_hooks()
{
    auto scanner_object = new scanner("EasyHook.dll");
    auto function_address = (void*)scanner_object->pattern_scan("40 55 48 83 EC 20 48 8D 0D ? ? ? ?");

    NTSTATUS(*LhUninstallFunctions)() = nullptr;
    LhUninstallFunctions = reinterpret_cast<decltype(LhUninstallFunctions)>(function_address);

    return LhUninstallFunctions() == 0 ? true : false; // STATUS_SUCCESS
}

/*

Pattern scanning section

*/

scanner::scanner(const char* module_name)
{
    this->module_address = reinterpret_cast<uintptr_t>(GetModuleHandleA(module_name));
}

std::vector<int> scanner::convert_pattern_to_byte(const char* pattern)
{
    auto bytes = std::vector<int>();

    auto pattern_start = const_cast<char*>(pattern) ;
    auto pattern_end = const_cast<char*>(pattern) + strlen(pattern);

    for (auto current_byte = pattern_start; current_byte < pattern_end; ++current_byte)
    {
        if (*current_byte == '?') // if it's null
        {
            ++current_byte;
            if (*current_byte == '?') ++current_byte;
            bytes.push_back(-1);
        }
        else bytes.push_back(strtoul(current_byte, &current_byte, 16));
    }

    return bytes;
}

void* scanner::pattern_scan(const char* pattern)
{
    auto dos_header = (IMAGE_DOS_HEADER*)this->module_address;
    auto nt_header = (IMAGE_NT_HEADERS*)((std::uint8_t*)this->module_address + dos_header->e_lfanew);

    auto size = nt_header->OptionalHeader.SizeOfImage;
    auto pattern_bytes = this->convert_pattern_to_byte(pattern);
    auto start_module = reinterpret_cast<std::uint8_t*>(this->module_address);

    for (auto i = 0; i < size - pattern_bytes.size(); ++i)
    {
        bool found_byte_set = true;
        for (auto j = 0; j < pattern_bytes.size(); ++j)
        {
            if (start_module[i + j] != pattern_bytes.data()[j] && pattern_bytes.data()[j] != -1)
            {
                found_byte_set = false;
                break;
            }
        }
        if (found_byte_set) return reinterpret_cast<void*>(&start_module[i]);
    }
    return nullptr;
}
