
#pragma once

#include "../util/structs.h"
namespace eggmem {

	class MemoryInternal
	{
	public:
		static PPEB getPEB();

		DWORD GetProcId();

		

		uint8_t* Scan(const char* module, const char* pattern);
#ifdef _WIN64
		constexpr void* Get(void* thisptr, const size_t index) noexcept
		{
			return (*static_cast<void***>(thisptr))[index];
		}

		
		template <typename T, typename ... U>
		constexpr T Call(void* thisptr, const size_t index, U ... params) noexcept
		{
			using Fn = T(__stdcall*)(void*, decltype(params)...); 
			return (*reinterpret_cast<Fn**>(thisptr))[index](thisptr, params...);
		}

		
		template <typename T = uintptr_t>
		constexpr T RelativeToAbsolute(const uintptr_t address) noexcept
		{
			return static_cast<T>(address + 4 + *reinterpret_cast<int32_t*>(address)); 
		}
#else
		constexpr void* Get(void* thisptr, const size_t index) noexcept
		{
			return (*static_cast<void***>(thisptr))[index];
			
		}

		
		template <typename T, typename ... U>
		constexpr T Call(void* thisptr, const size_t index, U ... params) noexcept
		{
			using Fn = T(__thiscall*)(void*, decltype(params)...);
			return (*static_cast<Fn**>(thisptr))[index](thisptr, params...);
		}

		
		template <typename T = uintptr_t>
		constexpr T RelativeToAbsolute(const uintptr_t address) noexcept
		{
			return static_cast<T>(address + 4 + *reinterpret_cast<uint32_t*>(address));
		}
#endif

		template<typename T>
		T read(uintptr_t address) {
			return *(T*)address;
		}

		template<typename T>
		void write(uintptr_t address, T value) {
			*(T*)address = value;
		}
		
	};

	
}

