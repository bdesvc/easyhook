#include "easyhook.hpp"

BOOL WINAPI beep_hk(DWORD dwFreq, DWORD dwDuration);

BOOL WINAPI beep_hk(DWORD dwFreq, DWORD dwDuration)
{
    return Beep(dwFreq, dwDuration + 1000); // add 100 to duration
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        auto hook_object = new easyhook;

        auto beep_address = GetProcAddress(GetModuleHandleA("kernel32.dll"), "Beep");
        if (!beep_address) MessageBoxA(0, "failed to find beep address :(", "easyhook", 0);

        HOOK_TRACE_INFO myhook = { NULL };
        hook_object->install_hook(beep_address, beep_hk, NULL, &myhook);
    }
    return TRUE;
}

