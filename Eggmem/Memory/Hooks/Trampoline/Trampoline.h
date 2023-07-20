#pragma once
#include "../Hook.h"

class Trampoline : public Hook {
public:
    Trampoline(uintptr_t hookAddress, BYTE* redirectFunctionAddress, size_t length)
        : Hook(hookAddress, redirectFunctionAddress), length(length), originalBytes(new BYTE[length])
    {
        memcpy(originalBytes.get(), (void*)hookAddress, length);
    }

    BYTE* install() override;

    bool uninstall() override;
        
    

private:
    size_t length;
    std::unique_ptr<BYTE[]> originalBytes; 
};