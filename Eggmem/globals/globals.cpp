#include "globals.h"

namespace eggmem {

	std::unique_ptr<Memory> g_pMemory = std::make_unique<Memory>();
	std::unique_ptr<Util> g_pUtil = std::make_unique<Util>();
	std::unique_ptr<MemoryInternal> g_pMemoryInternal = std::make_unique<MemoryInternal>();
	
}