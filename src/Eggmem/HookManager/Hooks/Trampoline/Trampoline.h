#pragma once
#include "../Hook.h"
#include <array>
#include <cstdint>
#include "../../../Util/Util.h"
#include "../../../Memory/Internal/Memory/Allocator/Allocator.h"

//class Trampoline : public Hook {
//public:
//    Trampoline(void* ogFunction, void* hookFunction, size_t length)
//        : Hook(ogFunction, hookFunction), length(length), originalBytes(new BYTE[length])
//    {
//        memcpy(originalBytes.get(), (void*)ogFunction, length);
//    }
//
//    BYTE* install() override;
//    void* FindSuitableMemory();
//    bool uninstall() override;
//        
//    
//
//private:
//    BYTE* gateway;
//    size_t length;
//    std::unique_ptr<BYTE[]> originalBytes; 
//};

class Trampoline : public Hook {
public:
    Trampoline(void* original, void* hookFunction, size_t length)
        : original(original), hookFunction(hookFunction), length(length), originalBytes(new BYTE[length])
    {
        safeCallVEH(__func__, [&] {
            memcpy(originalBytes.get(), (void*)original, length);
            });
    }

    BYTE* install() override;
    void* FindSuitableMemory();
    bool uninstall() override;
    uintptr_t getOriginalFunction() const override;
    
private:
    void* original;
    void* hookFunction;
    std::unique_ptr<Allocator> gatewayAllocator;
    BYTE* gateway;
    size_t length;
    std::unique_ptr<BYTE[]> originalBytes;
};