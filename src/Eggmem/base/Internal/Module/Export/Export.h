#pragma once
#include "../../../../Util/winapi.h"
#include "../../../../Util/Util.h"
#include "../../PE/PE.h"
class Export
{
public:

	Export(std::string exportName, uintptr_t exportAddress) : exportName(exportName), exportAddress(exportAddress) {};
	std::string name() { return exportName; }
	uintptr_t address() { return exportAddress; }
private:
	PE& pe = PE::get();
	std::string exportName;
	uintptr_t exportAddress;
};