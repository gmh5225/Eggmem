#pragma once
#include <memory>
#include "Thread/Thread.h"
#include <unordered_map>
#include "Module/Export/Export.h"
#include "Module/Import/Import.h"
#include "Module/Module.h"
#include "Memory/Allocator/Allocator.h"
#include "../../Util/Util.h"
#include "PE/PE.h"
#include "../../HookManager/HookManager.h"

enum Setup {
	noSetup,
	partialSetup,
	fullSetup
};

class Internal
{
public:
    
    
    Internal(const Internal&) = delete;
    Internal& operator=(const Internal&) = delete;

    static Internal& getInstance(int setup = Setup::partialSetup)
    {
        static Internal instance(setup);
        return instance;
    }

    ~Internal();

    std::vector<Thread> threads();
    std::vector<std::unique_ptr<Module>> modules();
    std::shared_ptr<Module> module(uintptr_t address);
    std::shared_ptr<Module> module(const std::string& name);
    HookManager& hooks = HookManager::get();
    PE& pe = PE::get();
    /*uintptr_t allocate(size_t size, DWORD protection);
    void deallocate(uintptr_t address);*/

private:
    Internal(int setup);

    std::unique_ptr<Thread> pThread;
    std::vector<Thread> _threads;
 /*   std::unordered_map<uintptr_t, std::unique_ptr<Module>> _modules;*/
    std::unordered_map<uintptr_t, std::shared_ptr<Module>> _modules;
    //std::unordered_map<uintptr_t, std::unique_ptr<Allocator>> _allocations;

    void handleLoadDllEvent(const LOAD_DLL_DEBUG_INFO& loadDllInfo);
    void handleUnloadDllEvent(const UNLOAD_DLL_DEBUG_INFO& unloadDllInfo);
    void debugLoop(DWORD processId);
};

//class Internal
//{
//public:
//
//    Internal(const Internal&) = delete;
//    Internal& operator=(const Internal&) = delete;
//
//    static Internal& getInstance(int setup = Setup::partialSetup)
//    {
//        static Internal instance(setup);
//        return instance;
//    }
//
//    ~Internal();
//
//    std::vector<Thread> threads();
//    std::vector<std::unique_ptr<Module>> modules();
//    std::unique_ptr<Module>& getModule(const std::string& name);
//    std::unique_ptr<Module>& getModule(uintptr_t address);
//
//    /*std::unique_ptr<Allocator> allocate(size_t size, DWORD protection);
//    bool free(uintptr_t address, size_t size, DWORD protection);*/
//
//    bool free(uintptr_t address);
//
//private:
//    Internal(int setup);
//
//    auto allocate(size_t size, DWORD protection) -> decltype(_allocations.begin());
//
//    void deallocate(decltype(_allocations.begin()) it);
//
//
//    std::unique_ptr<Thread> pThread;
//    std::vector<Thread> _threads;
//    /*std::vector<std::unique_ptr<Module>> _modules;*/
//    std::unordered_map<uintptr_t, std::unique_ptr<Module>> _modules;
//    std::unordered_map<uintptr_t, std::unique_ptr<Allocator>> _allocations;
//    PE& pe = PE::get();
//
//    void handleLoadDllEvent(const LOAD_DLL_DEBUG_INFO& loadDllInfo);
//    void handleUnloadDllEvent(const UNLOAD_DLL_DEBUG_INFO& unloadDllInfo);
//    void debugLoop(DWORD processId);
//};
//class Internal
//{
//	public:
//
//	Internal(int setup = Setup::partialSetup);
//	void debugLoop(DWORD processId);
//	void handleLoadDllEvent(const LOAD_DLL_DEBUG_INFO& loadDllInfo);
//	void handleUnloadDllEvent(const UNLOAD_DLL_DEBUG_INFO& unloadDllInfo);
//	~Internal();
//
//	std::vector<Thread> threads();
//	std::vector<Module> modules();
//	//Module getModule(const std::string& name);
//	//Module getModule(uintptr_t address);
//	std::vector<Module>::iterator getModule(const std::string& name);
//	std::vector<Module>::iterator getModule(uintptr_t address);
//
//private:
//	std::unique_ptr<Thread> pThread;
//	std::vector<Thread> _threads;
//	std::unique_ptr<Module> pModule;
//	std::vector<Module> _modules;
//	PE& pe = PE::get();
//};



