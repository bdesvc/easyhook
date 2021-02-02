#pragma once

#include <Windows.h>
#include <vector>

#define DEBUG

#ifdef DEBUG
#include <iostream>
#endif

/*

EasyHook.h structures

*/
typedef struct _LOCAL_HOOK_INFO_* PLOCAL_HOOK_INFO;

typedef struct _HOOK_TRACE_INFO_
{
	PLOCAL_HOOK_INFO        Link;
}HOOK_TRACE_INFO, * TRACED_HOOK_HANDLE;


class easyhook
{
public:
	bool install_hook(void* entrypoint, void* inhookproc, void* incallback, TRACED_HOOK_HANDLE out_handle); // 40 55 56 
	bool remove_hook(TRACED_HOOK_HANDLE in_handle); // 40 53 48 83 EC 20 48 8B D9 48 85 C9 0F 84 ? ? ? ? 48 83 F9 FF 0F 84 ? ? ? ? BA ? ? ? ? 48 89 7C 24 ? 
	bool remove_all_hooks(); // 40 55 48 83 EC 20 48 8D 0D ? ? ? ? 
};

class scanner : easyhook
{
private:
	uintptr_t module_address;
	std::vector<int> convert_pattern_to_byte(const char* pattern);
public:
	void* pattern_scan(const char* signature);

	scanner(const char* module_name);
};