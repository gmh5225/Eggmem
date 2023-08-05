#pragma once
#include "structs.h"
class Util
{
public:
    std::vector<DWORD> GetChildProcesses(DWORD parentProcessID);

    constexpr OBJECT_ATTRIBUTES InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security);

    bool Contains(const std::wstring& str, const std::wstring& substring);

};

extern void eggError(const std::string_view funcName, const std::string_view errorMessage);
#define EGG_ASSERT(condition, message) do { if(!(condition)) { eggError(__func__, message); } } while(false)
#define EGG_ERRORR(message) do { eggError(__func__, message); } while(false)}

bool Ensure(bool condition, const std::string_view funcName, const std::string_view message);

