#include "Internal.h"

Internal::Internal(int setup) {

	switch (setup) {
		case noSetup:
			break;
		case partialSetup:
			

			break;
		case fullSetup:
			break;
	}

}


std::shared_ptr<Module> Internal::module(uintptr_t address) {
    auto it = _modules.find(address);
    if (it == _modules.end()) {
        return safeCallVEH(__func__, [this, address]() {
            auto newModule = std::make_shared<Module>(address);
            _modules[address] = newModule;
            return newModule;
            });
    }
    return it->second;
}

std::shared_ptr<Module> Internal::module(const std::string& name) {
    for (const auto& [address, module] : _modules) {
        if (module->name() == name) {
            return module;
        }
    }

    return safeCallVEH(__func__, [this, &name]() {
        auto newModule = std::make_shared<Module>(name);
        uintptr_t address = newModule->base();
        _modules[address] = newModule;
        return newModule;
        });
}

//std::unique_ptr<Module>& Internal::module(uintptr_t address) {
//    return _modules[address];
//}
//std::unique_ptr<Module>& Internal::module(const std::string& name) {
//    for (auto& pair : _modules) {
//        if (pair.second->name() == name) {
//            return pair.second;
//        }
//    }
//
//    throw std::runtime_error("Module not found.");
//}


void Internal::debugLoop(DWORD processId) {
    DEBUG_EVENT debugEvent;
    while (true) {
        if (WaitForDebugEvent(&debugEvent, INFINITE)) {
            switch (debugEvent.dwDebugEventCode) {
            case LOAD_DLL_DEBUG_EVENT:

                safeCallSEH(__func__, [&]() {
					handleLoadDllEvent(debugEvent.u.LoadDll);
				});

                break;

            case UNLOAD_DLL_DEBUG_EVENT:
                safeCallSEH(__func__, [&]() {
                    handleUnloadDllEvent(debugEvent.u.UnloadDll);
                });
                break;

            }

            ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
        }
    }
}

//void Internal::handleLoadDllEvent(const LOAD_DLL_DEBUG_INFO& loadDllInfo) {
//    uintptr_t moduleBaseAddress = reinterpret_cast<uintptr_t>(loadDllInfo.lpBaseOfDll);
//
//    if (_modules.find(moduleBaseAddress) == _modules.end()) {
//        _modules[moduleBaseAddress] = std::make_unique<Module>(moduleBaseAddress);
//        std::cout << "Loaded module at: " << moduleBaseAddress << '\n';
//    }
//    else {
//        eggError(__func__, "Module already loaded.");
//    }
//}
//
//void Internal::handleUnloadDllEvent(const UNLOAD_DLL_DEBUG_INFO& unloadDllInfo) {
//    uintptr_t moduleBaseAddress = reinterpret_cast<uintptr_t>(unloadDllInfo.lpBaseOfDll);
//
//    auto it = _modules.find(moduleBaseAddress);
//    if (it != _modules.end()) {
//        _modules.erase(it);
//        std::cout << "Unloaded module at: " << moduleBaseAddress << '\n';
//    }
//    else {
//        // Module not found
//    }
//}

void Internal::handleLoadDllEvent(const LOAD_DLL_DEBUG_INFO& loadDllInfo) {
    uintptr_t moduleBaseAddress = reinterpret_cast<uintptr_t>(loadDllInfo.lpBaseOfDll);

    if (_modules.find(moduleBaseAddress) == _modules.end()) {
        _modules[moduleBaseAddress] = std::make_shared<Module>(moduleBaseAddress);
        std::cout << "Loaded module at: " << moduleBaseAddress << '\n';
    }
    else {
        EGG_ERROR("Module already loaded.");
    }
}

void Internal::handleUnloadDllEvent(const UNLOAD_DLL_DEBUG_INFO& unloadDllInfo) {
    uintptr_t moduleBaseAddress = reinterpret_cast<uintptr_t>(unloadDllInfo.lpBaseOfDll);

    auto it = _modules.find(moduleBaseAddress);
    if (it != _modules.end()) {
        _modules.erase(it);
        std::cout << "Unloaded module at: " << moduleBaseAddress << '\n';
    }
    else {
        EGG_ERROR("Module not found.");
    }
}