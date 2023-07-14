#pragma once
#include "../util/Util.h"
#include "../memory/Memory.h"
#include "../memory/MemoryInternal.h"

namespace eggmem {

	extern std::unique_ptr<Memory> g_pMemory;
	extern std::unique_ptr<Util> g_pUtil;
	extern std::unique_ptr<MemoryInternal> g_pMemoryInternal;


}
