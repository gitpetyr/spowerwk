#include <windows.h>
#include <MinHook.h>
#include <string>
#include <thread>
#include <winternl.h>
#include <fstream>
#include <mutex>

std::mutex g_logMutex;

void LogToFile(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::ofstream ofs("C:\\Windows\\System32\\spowerwk_dll.log", std::ios_base::app);
    if (ofs.is_open()) {
        ofs << msg << std::endl;
    }
}

// NtShutdownSystem
typedef enum _SHUTDOWN_ACTION {
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION;

extern "C" NTSYSAPI NTSTATUS NTAPI NtShutdownSystem(SHUTDOWN_ACTION Action);

// Global state
bool g_isGhostMode = false;
HANDLE g_hPipe = INVALID_HANDLE_VALUE;

// Original functions
typedef void(__fastcall* tShutdownWindowsWorkerThread)(PTP_CALLBACK_INSTANCE Instance, PVOID Context);
tShutdownWindowsWorkerThread Original_ShutdownWindowsWorkerThread = nullptr;

typedef __int64(__fastcall* tWlDisplayStatusByResourceId)(unsigned int a1, unsigned int a2, unsigned int a3, PVOID a4);
tWlDisplayStatusByResourceId Original_WlDisplayStatusByResourceId = nullptr;

// Query Python Service for shutdown policy
bool AskPythonServiceToBlockShutdown() {
    if (g_hPipe == INVALID_HANDLE_VALUE) return false;

    DWORD bytesWritten;
    // Include null terminator so Python's strip('\x00') and strcmp work correctly
    const char* req = "QUERY_SHUTDOWN\0";
    if (!WriteFile(g_hPipe, req, strlen(req) + 1, &bytesWritten, NULL)) {
        LogToFile("AskPythonServiceToBlockShutdown: Failed to write QUERY_SHUTDOWN to pipe.");
        return false;
    }

    char buf[16] = { 0 };
    DWORD bytesRead;
    if (ReadFile(g_hPipe, buf, sizeof(buf) - 1, &bytesRead, NULL)) {
        if (strcmp(buf, "BLOCK") == 0) {
            LogToFile("AskPythonServiceToBlockShutdown: Received strict BLOCK from service.");
            return true;
        } else if (strcmp(buf, "ALLOW") == 0) {
            LogToFile("AskPythonServiceToBlockShutdown: Received strict ALLOW from service.");
            return false;
        } else {
            LogToFile(std::string("AskPythonServiceToBlockShutdown: Received unknown response: ") + buf);
        }
    } else {
        LogToFile("AskPythonServiceToBlockShutdown: Failed to read response from pipe.");
    }
    
    // Fail-open: if service is unreachable or gives unknown response, allow shutdown.
    return false;
}

// Hooked ShutdownWindowsWorkerThread
void __fastcall Hooked_ShutdownWindowsWorkerThread(PTP_CALLBACK_INSTANCE Instance, PVOID Context) {
    if (g_isGhostMode) {
        LogToFile("Hooked_ShutdownWindowsWorkerThread: Ghost mode active. Secondary call detected. Triggering hard reboot!");
        // This is a secondary call (e.g. ACPI power button pressed during ghost mode)
        // Hard reboot to penalize/handle the physical button press
        // Acquire SeShutdownPrivilege
        HANDLE hToken;
        TOKEN_PRIVILEGES tkp;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
        LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
        
        LogToFile("Hooked_ShutdownWindowsWorkerThread: Reboot initiated.");
        NtShutdownSystem(ShutdownReboot);
        return; // We shouldn't reach here
    }

    LogToFile("Hooked_ShutdownWindowsWorkerThread: Intercepted primary shutdown call. Querying Service...");
    if (AskPythonServiceToBlockShutdown()) {
        LogToFile("Service replied BLOCK. Entering Ghost Mode and spoofing context.");
        g_isGhostMode = true;
        // Modify Context to force Logout (0) instead of Shutdown/Reboot
        Original_ShutdownWindowsWorkerThread(Instance, (PVOID)0);
    } else {
        LogToFile("Service replied ALLOW. Permitting normal shutdown.");
        // Allow normal shutdown
        Original_ShutdownWindowsWorkerThread(Instance, Context);
    }
}

// Hooked WlDisplayStatusByResourceId
__int64 __fastcall Hooked_WlDisplayStatusByResourceId(unsigned int a1, unsigned int a2, unsigned int a3, PVOID a4) {
    if (g_isGhostMode && a1 == 1003) {
        LogToFile("Hooked_WlDisplayStatusByResourceId: Spoofing logout UI (1003) to shutdown UI (1204).");
        // If we are in ghost mode (forced logout) and it tries to display "Logging off" (1003)
        // We spoof it to "Shutting down" (1204)
        a1 = 1204;
    }
    return Original_WlDisplayStatusByResourceId(a1, a2, a3, a4);
}

// Initialization Thread
DWORD WINAPI InitThread(LPVOID lpParam) {
    // 1. Connect to named pipe created by Python service
    while (true) {
        g_hPipe = CreateFileA("\\\\.\\pipe\\spowerwk_ipc", GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);
        if (g_hPipe != INVALID_HANDLE_VALUE) {
            break;
        }
        Sleep(1000);
    }

    // 2. Python service will send RVAs once connected
    // Format: "RVA:<ShutdownRVA>:<DisplayRVA>"
    char buf[128] = { 0 };
    DWORD bytesRead;
    if (!ReadFile(g_hPipe, buf, sizeof(buf) - 1, &bytesRead, NULL)) {
        CloseHandle(g_hPipe);
        return 0;
    }

    std::string msg(buf);
    if (msg.rfind("RVA:", 0) != 0) {
        CloseHandle(g_hPipe);
        return 0;
    }

    size_t firstColon = msg.find(':');
    size_t secondColon = msg.find(':', firstColon + 1);

    if (firstColon == std::string::npos || secondColon == std::string::npos) {
        CloseHandle(g_hPipe);
        return 0;
    }

    std::string shutdownRvaStr = msg.substr(firstColon + 1, secondColon - firstColon - 1);
    std::string displayRvaStr = msg.substr(secondColon + 1);

    uint64_t shutdownRva = std::stoull(shutdownRvaStr, nullptr, 16);
    uint64_t displayRva = std::stoull(displayRvaStr, nullptr, 16);

    // Get winlogon.exe base address
    HMODULE hModule = GetModuleHandleA(NULL);
    if (!hModule) {
        CloseHandle(g_hPipe);
        return 0;
    }

    void* targetShutdown = (void*)((uintptr_t)hModule + shutdownRva);
    void* targetDisplay = (void*)((uintptr_t)hModule + displayRva);

    // 3. Initialize MinHook and create hooks
    if (MH_Initialize() != MH_OK) {
        CloseHandle(g_hPipe);
        return 0;
    }

    if (shutdownRva != 0) {
        MH_CreateHook(targetShutdown, &Hooked_ShutdownWindowsWorkerThread, reinterpret_cast<LPVOID*>(&Original_ShutdownWindowsWorkerThread));
    }

    if (displayRva != 0) {
        MH_CreateHook(targetDisplay, &Hooked_WlDisplayStatusByResourceId, reinterpret_cast<LPVOID*>(&Original_WlDisplayStatusByResourceId));
    }

    MH_EnableHook(MH_ALL_HOOKS);

    // 4. Heartbeat loop
    while (true) {
        DWORD bytesWritten;
        // Include null terminator to match the null-terminated protocol used by the Python service
        const char* beat = "PING\0";
        if (!WriteFile(g_hPipe, beat, strlen(beat) + 1, &bytesWritten, NULL)) {
            // Broken pipe -> exit thread, DLL unloads or gets reinjected
            break;
        }
        Sleep(5000);
    }

    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    CloseHandle(g_hPipe);
    FreeLibraryAndExitThread((HMODULE)lpParam, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(NULL, 0, InitThread, hModule, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
    }
    return TRUE;
}
