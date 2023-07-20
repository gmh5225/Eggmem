#pragma once
#include "../Util/structs.h"

class Hook
{
public:
    Hook(uintptr_t hookAddress, BYTE* redirectFunctionAddress) : hookAddress(hookAddress), redirectFunctionAddress(redirectFunctionAddress), installed(false) {}

    virtual ~Hook() {}

    virtual BYTE* install() = 0;
    virtual bool uninstall() = 0;

    void Nop(BYTE* destination, uintptr_t size);
    void Patch(BYTE* destination, BYTE* source, uintptr_t size);

    //bool Detour32(BYTE* source, BYTE* redirectFunctionAddress, const uintptr_t length);
    //bool Detour64(BYTE* source, BYTE* destination, const uintptr_t length);

    //BYTE* TrampHook32(BYTE* source, BYTE* destination, const uintptr_t length);
    //BYTE* TrampHook64(BYTE* source, BYTE* destination, const uintptr_t length);;

    bool isHookInstalled() const {
        return installed;
    }

    uintptr_t getAddress() const {
        return hookAddress;
    }

protected:
    uintptr_t hookAddress;
    BYTE* redirectFunctionAddress;
    bool installed;
};

