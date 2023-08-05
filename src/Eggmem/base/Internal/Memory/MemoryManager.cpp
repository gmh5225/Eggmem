#include "MemoryManager.h"

MemoryManager::MemoryManager() {

}

MemoryManager::~MemoryManager() {
    allocations.clear();
}

uintptr_t MemoryManager::allocate(size_t size, DWORD protection, DWORD allocationType) {
    auto allocator = std::make_shared<Allocator>(size, protection, allocationType);
    if (allocator->address() != 0) {
        allocations[allocator->address()] = allocator;
    }
    return allocator->address(); 
}

void MemoryManager::deallocate(uintptr_t address) {
   
    allocations.erase(address);
}

void MemoryManager::deallocate(std::shared_ptr<Allocator> allocator) {
    if (allocator) {
        uintptr_t address = allocator->address();
        if (address != 0) {
            allocations.erase(address);
        }
    }
}

std::shared_ptr<Allocator> MemoryManager::getAllocatorByAddress(uintptr_t address) const {
    auto it = allocations.find(address);
    return (it != allocations.end()) ? it->second : nullptr;
}