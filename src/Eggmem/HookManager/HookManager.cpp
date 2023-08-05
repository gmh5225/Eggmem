#include "HookManager.h"
std::unordered_map<uintptr_t, std::unique_ptr<Hook>> HookManager::hooks;