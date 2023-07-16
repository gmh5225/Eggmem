#pragma once
#include "structs.h"
class Util
{
    std::vector<DWORD> GetChildProcesses(DWORD parentProcessID);

    OBJECT_ATTRIBUTES InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security);

};

static void eggError(const std::string_view funcName, const std::string_view errorMessage);
#define EGG_ASSERT(condition, message) do { if(!(condition)) { eggError(__func__, message); } } while(false)

bool Ensure(bool condition, const std::string_view funcName, const std::string_view message);
