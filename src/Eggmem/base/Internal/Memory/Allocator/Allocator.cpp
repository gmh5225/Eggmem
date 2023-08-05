#include "Allocator.h"


Allocator::Allocator(size_t size, DWORD protection, DWORD allocationType) : _size(size), _allocationType(allocationType), _protection(protection) {
	SIZE_T sz = size;
	NtAllocateVirtualMemory(NtCurrentProcess, (void**)&_address, 0, &sz, allocationType, protection);
}

Allocator::~Allocator() {
    if (_address != 0) {
        SIZE_T sz = 0;
        NtFreeVirtualMemory(NtCurrentProcess, (void**)&_address, &sz, MEM_RELEASE);
    }
}

uintptr_t Allocator::address() const {
    return _address;
}

size_t Allocator::size() const {
    return _size;
}

DWORD Allocator::allocationType() const {
    return _allocationType;
}

DWORD Allocator::protection() const {
    return _protection;
}