#pragma once
#include "../Hook.h"
#include <map>
class VMTHook : public Hook {
public:
    VMTHook(void* instance, uint16_t index, uintptr_t redirectedFunction)
        : instance(instance),
        vtableIndex(index),
        redirectedFunction(redirectedFunction)
    {
        originalVTable = *reinterpret_cast<void***>(instance);
        originalFunction = reinterpret_cast<uintptr_t>(originalVTable[index]);
    }

    virtual ~VMTHook() {}

    BYTE* install() override {
        originalVTable[vtableIndex] = reinterpret_cast<void*>(redirectedFunction);
        this->_installed = true;
        return nullptr;
    }

    bool uninstall() override {
        originalVTable[vtableIndex] = reinterpret_cast<void*>(originalFunction);
        this->_installed = false;
        return true;
    }

    uintptr_t getOriginalFunction() const override {
        return originalFunction;
    }

private:
    void* instance;
    uint16_t vtableIndex;
    uintptr_t redirectedFunction;
    uintptr_t originalFunction;
    void** originalVTable;
};

