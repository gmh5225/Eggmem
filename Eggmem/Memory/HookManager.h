#pragma once
#include "Util/structs.h"
#include "Hooks/Hook.h"
#include "Hooks/Trampoline/Trampoline.h"
//#include "Hooks/VTable"
#include <unordered_map>

class HookManager {
 
    public:
        
        /*bool installHook(uintptr_t address, BYTE* destination, hookMethods method) {
            
            switch (method) {
            case hookMethods::TRAMPOLINE:
				hooks.emplace_back(std::make_unique<Trampoline>(address, destination));
				break;
            default:
                return false;
            }
            return hooks.back()->install();
        }*/

        template<typename T, typename... Args>
        bool installHook(Args&&... args) {
            hooks.emplace_back(std::make_unique<T>(std::forward<Args>(args)...));
            return hooks.back()->install();
        }

        bool uninstallHook(uintptr_t address) {
            for (auto& hook : hooks) {
                if (hook->getAddress() == address) {
                    return hook->uninstall();
                }
            }
            return false;
        }

    private:
        std::vector<std::unique_ptr<Hook>> hooks;
    };


    //template <typename HookType, typename... Args>
    //void addHook(Args&&... args) {
    //    auto hook = std::make_unique<HookType>(std::forward<Args>(args)...);
    //    uintptr_t address = hook->address;
    //    HookMethods method = hook->method;
    //    hooksByAddress[address] = std::move(hook);
    //    hooksByMethod[method].push_back(hooksByAddress[address].get());
    //}

    //Hook* findHookByAddress(uintptr_t address) {
    //    auto it = hooksByAddress.find(address);
    //    if (it != hooksByAddress.end()) {
    //        return it->second.get();
    //    }
    //    else {
    //        return nullptr;
    //    }
    //}
    //std::vector<Hook*> findHooksByMethod(hookMethods method) {
    //    auto it = hooksByMethod.find(method);
    //    if (it != hooksByMethod.end()) {
    //        return it->second;
    //    }
    //    else {
    //        return std::vector<Hook*>();
    //    }
    //}

    //bool removeHook(uintptr_t address) {
    //    auto it = hooksByAddress.find(address);
    //    if (it == hooksByAddress.end()) {
    //        // No hook found with the given address.
    //        return false;
    //    }

    //    Hook* hook = it->second.get();
    //    this->uninstallHook();

    //    auto method_it = hooksByMethod.find(hook->method);
    //    if (method_it != hooksByMethod.end()) {
    //        auto& hooks = method_it->second;
    //        hooks.erase(std::remove(hooks.begin(), hooks.end(), hook), hooks.end());
    //    }

    //    hooksByAddress.erase(it);

    //    return true;
    //}



