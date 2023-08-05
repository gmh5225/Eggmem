#include "VTable.h"

VMTHook::VMTHook(void* instance, uint16_t index, uintptr_t redirectedFunction)
    : instance(instance),
    vtableIndex(index),
    redirectedFunction(redirectedFunction)
{
    originalVTable = *reinterpret_cast<void***>(instance);
    originalFunction = reinterpret_cast<uintptr_t>(originalVTable[index]);
}

VMTHook::~VMTHook() {}

BYTE* VMTHook::install() {
    originalVTable[vtableIndex] = reinterpret_cast<void*>(redirectedFunction);
    this->_installed = true;
    return nullptr;
}

bool VMTHook::uninstall() {
    originalVTable[vtableIndex] = reinterpret_cast<void*>(originalFunction);
    this->_installed = false;
    return true;
}

uintptr_t VMTHook::getOriginalFunction() const {
    return originalFunction;
}