#pragma once
#include "../Hook.h"
#include <unordered_map>

#ifdef _WIN64
#define XIP Rip
#else
#define XIP Eip
#endif

class VEH : public Hook
{
public:
	VEH(void* original, void* hookFunction)
		: Hook(), original(original), hookFunction(hookFunction) {};
		
	BYTE* install() override;
	static long __stdcall Handler(EXCEPTION_POINTERS* pExceptionInfo);
	bool uninstall() override;
	bool areFunctionsInTheSamePage(void* function1, void* function2);
	uintptr_t getOriginalFunction() const override;

private:
	void* original;
	void* hookFunction;
	static std::unordered_map<void*, VEH*> instancesMap;
	unsigned long oldProtection;
	void* VEHHandle;

};

