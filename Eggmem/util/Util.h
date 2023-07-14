
#pragma once

#include "structs.h"


namespace eggmem {

    class Util {
    public:

        

        void eggError(const std::string_view funcName, const std::string_view errorMessage);

        std::vector<DWORD> GetChildProcesses(DWORD parentProcessID);

        OBJECT_ATTRIBUTES InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security);

    };
    

    
}
