#include "Eggmem.h"

Eggmem::Eggmem(std::wstring processName) {
	this->external = std::make_unique<External>(processName);
	this->internal = std::make_unique<Internal>();
}

std::unique_ptr<External> Eggmem::getExternal() {
	return std::move(this->external);
}

std::unique_ptr<Internal> Eggmem::getInternal() {
	return std::move(this->internal);
}