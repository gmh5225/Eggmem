#pragma once
#include "Eggmem/Memory/External/External.h"
#include "Eggmem/Memory/Internal/Internal.h"
	class Eggmem {

	public:
		Eggmem(std::wstring processName);
		

		std::unique_ptr<External> getExternal();
		std::unique_ptr<Internal> getInternal();

	private:
		std::unique_ptr<External> external;
		std::unique_ptr<Internal> internal;
	};
	
    

