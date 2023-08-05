#pragma once
#include "../../../../Util/winapi.h"
#include "../../../../Util/Util.h"
#include "../../PE/PE.h"
class Import
{
public:

	Import(std::string importName, uintptr_t importAddress) : importName(importName), importAddress(importAddress) {};
	std::string name();
	uintptr_t address();
private:
	PE& pe = PE::get();
	std::string importName;
	uintptr_t importAddress;
};

