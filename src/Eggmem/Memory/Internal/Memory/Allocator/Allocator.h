#include <Windows.h>
#include "../../../../Util/winapi.h"
#include "../../../../Util/Util.h"
#include <unordered_map>
//class Allocator
//{
//public:
//    Allocator(size_t size, DWORD protection, DWORD allocationType = MEM_COMMIT | MEM_RESERVE)
//        : _size(size),
//        _allocationType(allocationType),
//        _protection(protection)
//    {
//        
//        SIZE_T sz = size;
//        NTSTATUS status = NtAllocateVirtualMemory(NtCurrentProcess, (void**)&_address, 0, &sz, allocationType, protection);
//        if (!NT_SUCCESS(status)) {
//            
//            _address = 0;
//        }
//    }
//
//    ~Allocator() {
//        if (_address != 0) {
//            SIZE_T sz = 0;
//            NtFreeVirtualMemory(NtCurrentProcess, (void**)&_address, &sz, MEM_RELEASE);
//        }
//    }
//
//    uintptr_t address() const { return _address; }
//    size_t size() const { return _size; }
//    DWORD allocationType() const { return _allocationType; }
//    DWORD protection() const { return _protection; }
//
//private:
//    uintptr_t _address;
//    size_t _size;
//    DWORD _allocationType;
//    DWORD _protection;
//};

class Allocator
{
public:
    Allocator(size_t size, DWORD protection, DWORD allocationType = MEM_COMMIT | MEM_RESERVE)
        : _size(size),
        _allocationType(allocationType),
        _protection(protection)
    {
        SIZE_T sz = size;
        NTSTATUS status = NtAllocateVirtualMemory(NtCurrentProcess, (void**)&_address, 0, &sz, allocationType, protection);
        if (!NT_SUCCESS(status)) {
            _address = 0;
        }
        else {
            instances[_address] = this;
        }
    }

    ~Allocator() {
        if (_address != 0) {
            
            instances.erase(_address);
            SIZE_T sz = 0;
            NtFreeVirtualMemory(NtCurrentProcess, (void**)&_address, &sz, MEM_RELEASE);
        }
    }

    static void deallocate(uintptr_t address) {
        auto it = instances.find(address);
        if (it != instances.end()) {
            delete it->second;
        } 
    }

    uintptr_t address() const { return _address; }
    size_t size() const { return _size; }
    DWORD allocationType() const { return _allocationType; }
    DWORD protection() const { return _protection; }

private:
    uintptr_t _address;
    size_t _size;
    DWORD _allocationType;
    DWORD _protection;

    static std::unordered_map<uintptr_t, Allocator*> instances; // static member to track instances
};

std::unordered_map<uintptr_t, Allocator*> Allocator::instances;