#pragma once
#include "../Util/winapi.h"
#include <vector>
#include <memory>
#include "Hooks/Trampoline/Trampoline.h"
#include "Hooks/VTable/VTable.h"
#include "Hooks/VEH/VEH.h"
//#include "Hooks/VTable"
#include <unordered_map>

//class HookManager {
//public:
//
//    static HookManager& get() {
//        static HookManager instance; // Guaranteed to be destroyed and instantiated on first use.
//        return instance;
//    }
//
//    HookManager(const HookManager&) = delete;
//    void operator=(const HookManager&) = delete;
//
//    template<typename T, typename... Args>
//    bool installHook(Args&&... args) {
//        //stopThreads();
//        hooks.emplace_back(std::make_unique<T>(std::forward<Args>(args)...));
//        bool result = safeCallSEH([&]() { 
//                return hooks.back()->install();
//        });
//        
//        return result;
//    }
//
//    template<typename T, typename... Args>
//    T* setupHook(Args&&... args) {
//        auto hook = std::make_unique<T>(std::forward<Args>(args)...);
//        T* rawHookPtr = hook.get();
//        hooks.emplace_back(std::move(hook));
//        return rawHookPtr;
//    }
//
//    bool uninstallHook(uintptr_t address) {
//            for (auto& hook : hooks) {
//                if (hook->getAddress() == address) {
//                    return hook->uninstall();
//                }
//            }
//            return false;
//
//    }
//
//private:
//    HookManager() {} 
//    std::vector<std::unique_ptr<Hook>> hooks;
//
//};

class HookManager {
public:
    static HookManager& get() {
        static HookManager instance;
        return instance;
    }

    HookManager(const HookManager&) = delete;
    HookManager& operator=(const HookManager&) = delete;

    template<typename T, typename... Args>
    T* create(Args&&... args) {
        auto hook = std::make_unique<T>(std::forward<Args>(args)...);
        uintptr_t address = hook->getAddress();

        if (hooks.find(address) != hooks.end()) {
            std::cout << "Hook already exists at address: " << std::hex << address << ". Calling install will override the currently installed hook." << std::endl;
            return nullptr;
        }

        hooks[address] = std::move(hook);
        return static_cast<T*>(hooks[address].get());
    }

    bool uninstall(Hook* hook) {
        if (!hook) {
            return false;
        }

        uintptr_t address = hook->getOriginalFunction();
        auto it = hooks.find(address);
        if (it != hooks.end()) {
            if (hook->uninstall()) {
                hooks.erase(it);
                return true;
            }
        }
        return false;
    }

    bool uninstall(uintptr_t address) {
        auto it = hooks.find(address);
        if (it != hooks.end()) {
            if (it->second->uninstall()) {
				hooks.erase(it);
				return true;
			}
		}
    }

    bool install(Hook* hook) {
        if (hook == nullptr) {
            return false;
        }

        uintptr_t address = hook->getOriginalFunction();

        if (hooks.find(address) != hooks.end() && hooks[address]->installed()) {
            std::cout << "Hook already installed at address: " << std::hex << address << ". Overriding..." << std::endl;
            hooks[address]->uninstall();
        }

        if (hook->install()) {
            return true;
        }

        hooks.erase(address);
        return false;
    }

    

    Hook* getHook(uintptr_t address) {
        auto it = hooks.find(address);
        return (it != hooks.end()) ? it->second.get() : nullptr;
    }

    ~HookManager() {
        for (auto& pair : hooks) {
            pair.second->uninstall();
        }
    }

private:
    HookManager() {}

    static std::unordered_map<uintptr_t, std::unique_ptr<Hook>> hooks;
};


