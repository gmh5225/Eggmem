#include "Allocator.h"
std::unordered_map<uintptr_t, Allocator*> Allocator::instances;