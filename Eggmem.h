#pragma once
#include "Eggmem/memory/util/Util.h"
#include "Eggmem/memory/Memory.h"
#include "Eggmem/memory/MemoryInternal.h"

namespace eggmem {
	class Eggmem {
	public:
		std::unique_ptr<Memory> pMemory = std::make_unique<Memory>();
		std::unique_ptr<Util> pUtil = std::make_unique<Util>();
		std::unique_ptr<MemoryInternal> pMemoryInternal = std::make_unique<MemoryInternal>();
	};
	
    
}
