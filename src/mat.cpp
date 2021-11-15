#include "../include/MinHook.h"
// #include <cassert>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <intrin.h>
#include <unordered_set>
#include <fstream>
#include <filesystem>
#include "hook.h"

#pragma intrinsic(_ReturnAddress)

template <class T, class U>
inline T cast(U value) {
    return reinterpret_cast<T>(value);
}

void _assert(bool value, const char* code, int line, const char* func) {
    if (!value) {
        std::stringstream stream;
        stream << "Assertion failed on line " << line << "on function " << func << ":" << std::endl;
        stream << code;
        // MessageBoxA(NULL, stream.str().c_str(), "Assertion failed", MB_OK | MB_ICONWARNING);
        //exit(1);
    }
}

#define assert(expr) _assert((expr), #expr, __LINE__, __FUNCTION__)

struct Detour {
    // a bit wasteful to store this here but whatever
    void* target;
    void* addr;
    void* trampoline;
    bool enabled;

    bool operator==(const Detour& b) const {
        return target == b.target && addr == b.addr && trampoline == b.trampoline;
    }
};

struct Hook {
    void* addr;
    std::vector<Detour> detours;
    uint8_t replacedByte;
};

struct QueueItem {
    void* mod;
    void* target;
    bool toggle;
};

static struct {
    std::unordered_map<void*, Hook> hooks;
    // trampoline addr -> Hook
    std::unordered_map<void*, Hook*> trampolines;
    // stores which hook is currently being single stepped
    Hook* stepHook = nullptr;
    void* vectorHandle = nullptr;
    // all the hooks created by a module
    std::unordered_map<void*, std::unordered_set<Detour*>> moduleHooks;
    std::vector<QueueItem> queue;
} state;

void patch(void* const addr, const std::vector<uint8_t>& bytes) {
    WriteProcessMemory(GetCurrentProcess(), addr, bytes.data(), bytes.size(), nullptr);
}

static long WINAPI handler(EXCEPTION_POINTERS* info) {
    const auto code = info->ExceptionRecord->ExceptionCode;
    const auto addr = info->ExceptionRecord->ExceptionAddress;
    #if defined(_M_X64) || defined(__x86_64__)
    auto& eip = *cast<void**>(&info->ContextRecord->Rip);
    #else
    auto& eip = *cast<void**>(&info->ContextRecord->Eip);
    #endif
    // Jumps back to the original function by replacing
    // the replaced byte back, and also enabling the 
    // single step flag on the cpu
    // This is later dealt with in the EXCEPTION_SINGLE_STEP block
    const auto jumpOriginal = [&](Hook& hook) {
        info->ContextRecord->EFlags |= 0x100;
        patch(hook.addr, {hook.replacedByte});
        eip = hook.addr;
        state.stepHook = &hook;
        return EXCEPTION_CONTINUE_EXECUTION;
    };
    if (code == EXCEPTION_BREAKPOINT) {
        auto pair = state.hooks.find(addr);
        if (pair != state.hooks.end()) {
            auto& hook = pair->second;
            for (auto& detour : hook.detours) {
                if (detour.enabled) {
                    eip = detour.addr;
			        return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            // None of the hooks are enabled, so just jump back to the original function
            return jumpOriginal(hook);
        } else {
            auto pair = state.trampolines.find(addr);
            if (pair != state.trampolines.end()) {
                auto& hook = *pair->second;
                // TODO: somehow get rid of this for loop
                for (size_t i = 0; i < hook.detours.size() - 1; ++i) {
                    if (hook.detours[i].trampoline == addr) {
                        // find next enabled hook
                        for (size_t j = i + 1; j < hook.detours.size() - 1; ++j) {
                            const auto& detour = hook.detours[j];
                            if (detour.enabled) {
                                eip = detour.addr;
                                return EXCEPTION_CONTINUE_EXECUTION;
                            }
                        }
                        break;
                    }
                }
                // we've reached the end of the chain, go back to the original function
                return jumpOriginal(hook);
            }
        }
    } else if (code == EXCEPTION_SINGLE_STEP && state.stepHook) {
        patch(state.stepHook->addr, {0xCC});
        state.stepHook = nullptr;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
	return EXCEPTION_CONTINUE_SEARCH;
}

void* getModuleByAddress(void* addr) {
    HMODULE handle = NULL;
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCTSTR)addr, &handle);
    return cast<void*>(handle);
}

std::string getModuleName(void* module) {
	char buffer[MAX_PATH];
	if (!GetModuleFileNameA(cast<HMODULE>(module), buffer, MAX_PATH))
		return "Unknown";
	return std::filesystem::path(buffer).filename().string();
}

template <class T, class P>
void erase_if(T& container, P pred) {
    container.erase(std::remove_if(container.begin(), container.end(), pred));
}

std::ofstream log() {
    std::ofstream file;
    file.open("minhooklog.log", std::ios::app);
    return file;
}

template <class T>
struct ScopeGuard {
    T func;
    ScopeGuard(T func) : func(func) {}
    ~ScopeGuard() {
        func();
    }
};

#define STRCAT_(a, b) a##b
#define STRCAT(a, b) STRCAT_(a, b)
#define guard ScopeGuard STRCAT(__guard, __LINE__)

#define spinLock() EnterSpinLock(); guard([]() { LeaveSpinLock(); })

extern "C" {
    MH_STATUS WINAPI MH_Initialize() {
        spinLock();
        log() << "MH_Initialize" << std::endl;
        if (state.vectorHandle) return MH_ERROR_ALREADY_INITIALIZED;
        log() << "MH_Initialize successful" << std::endl;
        if (state.vectorHandle = AddVectoredExceptionHandler(true, handler)) {
            return MH_OK;
        }
        return MH_UNKNOWN;
    }

    MH_STATUS WINAPI MH_Uninitialize() {
        spinLock();
        log() << "MH_Uninitialize" << std::endl;
        return MH_OK;
        // if (state.vectorHandle == nullptr) return MH_ERROR_NOT_INITIALIZED;
        // for (const auto& pair : state.hooks) {
        //     const auto& hook = pair.second;
        //     patch(hook.addr, {hook.replacedByte});
        //     for (const auto& detour : hook.detours) {
        //         VirtualFree(detour.trampoline, 0, MEM_RELEASE | MEM_DECOMMIT);
        //     }
        // }
        // state.trampolines.clear();
        // state.hooks.clear();

        // AKA remove all my hooks

        auto calleeModule = getModuleByAddress(_ReturnAddress());
        auto pair = state.moduleHooks.find(calleeModule);
        if (pair != state.moduleHooks.end()) {
            auto& set = pair->second;
            for (const auto detour : set) {
                state.trampolines.erase(detour->trampoline);
                VirtualFree(detour->trampoline, 0, MEM_RELEASE | MEM_DECOMMIT);
                auto& detours = state.hooks[detour->target].detours;
                // this is so dumb lmao cuz theres only ever one detour
                // maybe switch from vector to ordered_set ?
                detours.erase(std::remove(detours.begin(), detours.end(), *detour));
            }
            state.moduleHooks.erase(calleeModule);
        }

        // // TODO: maybe check if this fails
        // RemoveVectoredExceptionHandler(state.vectorHandle);
        // state.vectorHandle = nullptr;
        return MH_OK;
    }

    MH_STATUS WINAPI MH_CreateHook(void* target, void* detour, void** original) {
        spinLock();
        auto calleeModule = getModuleByAddress(_ReturnAddress());
        log() << "MH_CreateHook by " << getModuleName(calleeModule) << std::endl;
        // TODO: hooks are enabled by default (stupid minhook)
        // i have to create them in a state where theyre disabled but can also be queued enabled which doesnt
        // enable them right away
        auto pair = state.hooks.find(target);
        auto& hook = pair != state.hooks.end() ? pair->second : (state.hooks[target] = Hook {
            target, {}, *cast<uint8_t*>(target)
        });
        if (pair == state.hooks.end()) {
            patch(target, {0xCC});
        }
        
        *original = VirtualAlloc(nullptr, 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        patch(*original, {0xCC});
        hook.detours.insert(hook.detours.begin(), Detour {
            target, detour, *original, false
        });
        state.trampolines[*original] = &hook;
        {
            auto pair = state.moduleHooks.find(calleeModule);
            auto& set = pair != state.moduleHooks.end() ? pair->second : (state.moduleHooks[calleeModule] = {});
            set.insert(&hook.detours.back());
        }
        return MH_OK;
    }

    MH_STATUS WINAPI MH_RemoveHook(void* target) {
        spinLock();
        auto calleeModule = getModuleByAddress(_ReturnAddress());
        log() << "MH_RemoveHook by " << getModuleName(calleeModule) << std::endl;
        auto pair = state.moduleHooks.find(calleeModule);
        if (pair != state.moduleHooks.end()) {
            auto& set = pair->second;
            for (const auto detour : set) {
                if (detour->target == target) {
                    state.trampolines.erase(detour->trampoline);
                    VirtualFree(detour->trampoline, 0, MEM_RELEASE | MEM_DECOMMIT);
                }
            }
            auto pair = state.hooks.find(target);
            if (pair != state.hooks.end()) {
                auto& hook = pair->second;
                erase_if(hook.detours, [&](Detour& detour){ return set.count(&detour) > 0; });
                // TODO: maybe check if hook.detours became empty
                // then remove the hook entirely
            }
            for (const auto detour : set) {
                if (detour->target == target) {
                    set.erase(detour);
                }
            }
        }
        return MH_OK;
    }

    MH_STATUS WINAPI MH_EnableHook(void* target) {
        spinLock();
        auto calleeModule = getModuleByAddress(_ReturnAddress());
        log() << "MH_EnableHook by " << getModuleName(calleeModule) << std::endl;
        auto pair = state.moduleHooks.find(calleeModule);
        if (pair != state.moduleHooks.end()) {
            for (auto detour : pair->second) {
                if (target == MH_ALL_HOOKS || detour->target == target)
                    detour->enabled = true;
            }
        }
        return MH_OK;
    }

    MH_STATUS WINAPI MH_DisableHook(void* target) {
        spinLock();
        auto calleeModule = getModuleByAddress(_ReturnAddress());
        log() << "MH_DisableHook by " << getModuleName(calleeModule) << std::endl;
        auto pair = state.moduleHooks.find(calleeModule);
        if (pair != state.moduleHooks.end()) {
            for (auto detour : pair->second) {
                if (target == MH_ALL_HOOKS || detour->target == target)
                    detour->enabled = false;
            }
        }
        return MH_OK;
    }

    MH_STATUS WINAPI MH_QueueEnableHook(void* target) {
        spinLock();
        auto calleeModule = getModuleByAddress(_ReturnAddress());
        log() << "MH_QueueEnableHook by " << getModuleName(calleeModule) << std::endl;
        state.queue.push_back(QueueItem {
            calleeModule,
            target,
            true
        });
        return MH_OK;
    }

    MH_STATUS WINAPI MH_QueueDisableHook(void* target) {
        spinLock();
        auto calleeModule = getModuleByAddress(_ReturnAddress());
        log() << "MH_QueueDisableHook by " << getModuleName(calleeModule) << std::endl;
        state.queue.push_back(QueueItem {
            calleeModule,
            target,
            false
        });
        return MH_OK;
    }

    MH_STATUS WINAPI MH_ApplyQueued() {
        spinLock();
        for (const auto& item : state.queue) {
            auto pair = state.moduleHooks.find(item.mod);
            if (pair != state.moduleHooks.end()) {
                for (auto detour : pair->second) {
                    if (item.target == MH_ALL_HOOKS || detour->target == item.target)
                        detour->enabled = item.toggle;
                }
            }
        }
        state.queue.clear();
        return MH_OK;
    }

}
