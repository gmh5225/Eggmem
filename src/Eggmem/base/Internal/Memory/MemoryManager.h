#pragma once
#include "Allocator/Allocator.h"
class MemoryManager {
public:
    MemoryManager(const MemoryManager&) = delete;
    MemoryManager& operator=(const MemoryManager&) = delete;
    static MemoryManager& get() {
        static MemoryManager instance;
        return instance;
    }
    ~MemoryManager();

    uintptr_t allocate(size_t size, DWORD protection, DWORD allocationType = MEM_COMMIT | MEM_RESERVE);

    void deallocate(uintptr_t address);
    void deallocate(std::shared_ptr<Allocator> allocator);

    std::shared_ptr<Allocator> getAllocatorByAddress(uintptr_t address) const;

private:
    MemoryManager();
    std::unordered_map<uintptr_t, std::shared_ptr<Allocator>> allocations;
};

