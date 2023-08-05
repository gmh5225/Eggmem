#pragma once
#include "../Util/winapi.h"
#include <vector>
#include <memory>
#include "Hooks/Trampoline/Trampoline.h"
#include "Hooks/VTable/VTable.h"
#include "Hooks/VEH/VEH.h"
//#include "Hooks/VTable"
#include <unordered_map>

class HookManager {
public:
    static HookManager& get() {
        static HookManager instance;
        return instance;
    }

    HookManager(const HookManager&) = delete;
    HookManager& operator=(const HookManager&) = delete;

    template<typename T, typename... Args>
    std::shared_ptr<T> create(Args&&... args) {
        auto hook = std::make_shared<T>(std::forward<Args>(args)...);
        uintptr_t address = hook->getAddress();

        if (hooks.find(address) != hooks.end()) {
            std::cout << "Hook already exists at address: " << std::hex << address << ". Calling install will override the currently installed hook." << std::endl;
            return hook;
        }

        hooks[address] = hook;
        return hook;
    }

    template<typename T, typename... Args>
    std::shared_ptr<T> createAndInstall(Args&&... args) {
        auto hook = std::make_shared<T>(std::forward<Args>(args)...);

        install(hook);
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
        return false;
    }

    bool install(std::shared_ptr<Hook> hook) {
        if (!hook) {
            return false;
        }

        uintptr_t address = hook->getOriginalFunction();

        if (hooks.find(address) != hooks.end() && hooks[address]->installed()) {
            std::cout << "Hook already installed at address: " << std::hex << address << ". Overriding..." << std::endl;
            hooks[address]->uninstall();
        }

        if (hook->install()) {
            hooks[address] = hook;
            return true;
        }

        hooks.erase(address);
        return false;
    }

    std::shared_ptr<Hook> getHook(uintptr_t address) {
        auto it = hooks.find(address);
        if (it != hooks.end()) {
            return it->second;
        }
        return nullptr;
    }

    ~HookManager() {
        for (auto& pair : hooks) {
            pair.second->uninstall();
        }
    }

private:
    HookManager() {}

    std::unordered_map<uintptr_t, std::shared_ptr<Hook>> hooks;
};

//class HookManager {
//public:
//    static HookManager& get() {
//        static HookManager instance;
//        return instance;
//    }
//
//    HookManager(const HookManager&) = delete;
//    HookManager& operator=(const HookManager&) = delete;
//
//    template<typename T, typename... Args>
//    T* create(Args&&... args) {
//        auto hook = std::make_unique<T>(std::forward<Args>(args)...);
//        uintptr_t address = hook->getAddress();
//
//        if (hooks.find(address) != hooks.end()) {
//            std::cout << "Hook already exists at address: " << std::hex << address << ". Calling install will override the currently installed hook." << std::endl;
//            return nullptr;
//        }
//
//        hooks[address] = std::move(hook);
//        return static_cast<T*>(hooks[address].get());
//    }
//
//    bool uninstall(Hook* hook) {
//        if (!hook) {
//            return false;
//        }
//
//        uintptr_t address = hook->getOriginalFunction();
//        auto it = hooks.find(address);
//        if (it != hooks.end()) {
//            if (hook->uninstall()) {
//                hooks.erase(it);
//                return true;
//            }
//        }
//        return false;
//    }
//
//    bool uninstall(uintptr_t address) {
//        auto it = hooks.find(address);
//        if (it != hooks.end()) {
//            if (it->second->uninstall()) {
//				hooks.erase(it);
//				return true;
//			}
//		}
//    }
//
//    bool install(Hook* hook) {
//        if (hook == nullptr) {
//            return false;
//        }
//
//        uintptr_t address = hook->getOriginalFunction();
//
//        if (hooks.find(address) != hooks.end() && hooks[address]->installed()) {
//            std::cout << "Hook already installed at address: " << std::hex << address << ". Overriding..." << std::endl;
//            hooks[address]->uninstall();
//        }
//
//        if (hook->install()) {
//            return true;
//        }
//
//        hooks.erase(address);
//        return false;
//    }
//
//    
//
//    Hook* getHook(uintptr_t address) {
//        auto it = hooks.find(address);
//        return (it != hooks.end()) ? it->second.get() : nullptr;
//    }
//
//    ~HookManager() {
//        for (auto& pair : hooks) {
//            pair.second->uninstall();
//        }
//    }
//
//private:
//    HookManager() {}
//
//    static std::unordered_map<uintptr_t, std::unique_ptr<Hook>> hooks;
//};


