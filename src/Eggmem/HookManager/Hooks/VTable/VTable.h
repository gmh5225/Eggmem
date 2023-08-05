#pragma once
#include "../Hook.h"
#include <map>
class VMTHook : public Hook {
public:
    VMTHook(void* instance, uint16_t index, uintptr_t redirectedFunction);
    virtual ~VMTHook();

    BYTE* install() override;
    bool uninstall() override;

    uintptr_t getOriginalFunction() const override;

private:
    void* instance;
    uint16_t vtableIndex;
    uintptr_t redirectedFunction;
    uintptr_t originalFunction;
    void** originalVTable;
};

