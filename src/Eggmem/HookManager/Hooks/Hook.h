#pragma once
#include "../../Util/winapi.h"
class Hook
{
public:
    Hook() : _installed(false) {}

    virtual ~Hook() {}

    virtual BYTE* install() = 0;
    
    virtual bool uninstall() = 0;

    bool installed() const {
        return _installed;
    }


    virtual uintptr_t getOriginalFunction() const = 0;
    

protected:
    bool _installed;
};

