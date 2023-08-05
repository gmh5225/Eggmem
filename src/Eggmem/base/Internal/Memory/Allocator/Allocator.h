#pragma once
#include <Windows.h>
#include "../../../../Util/winapi.h"
#include "../../../../Util/Util.h"
#include <unordered_map>
#include <mutex>


class Allocator {
public:
    Allocator(size_t size, DWORD protection, DWORD allocationType = MEM_COMMIT | MEM_RESERVE);
    ~Allocator();

    uintptr_t address() const;
    size_t size() const;
    DWORD allocationType() const;
    DWORD protection() const;

private:
    uintptr_t _address;
    size_t _size;
    DWORD _allocationType;
    DWORD _protection;

    
    
};

