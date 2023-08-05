#include "BreakpointHook.h"
std::unordered_map<uintptr_t, BreakpointHook*> BreakpointHook::globalHookMap;
