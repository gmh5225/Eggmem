#include "Import.h"

std::string Import::name()
{
	return this->importName;
}

uintptr_t Import::address()
{
	return this->importAddress;
}
