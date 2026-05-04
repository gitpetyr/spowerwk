#include <windows.h>
#include <MinHook.h>
#include <string>
#include <thread>
#include <winternl.h>
#include <fstream>
#include <mutex>
#include <atomic>
#include <powrprof.h>
#pragma comment(lib, "powrprof.lib")
// SetProcessValidCallTargets is declared in memoryapi.h (included by windows.h)

std::mutex g_logMutex;
HANDLE g_hPipe = INVALID_HANDLE_VALUE;

// Log via IPC pipe so the Python service writes to the unified log file.
// Falls back to C:\Users\Public\spowerwk_dll.log only when pipe is unavailable
// (e.g. very early init before connection is established).
void LogToFile(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::ofstream ofs("C:\\Users\\Public\\spowerwk_dll.log", std::ios_base::app);
    if (ofs.is_open()) {
        ofs << msg << std::endl;
    }
}

void LogToPipe(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_hPipe == INVALID_HANDLE_VALUE) {
        // Pipe not yet open; use file fallback.
        std::ofstream ofs("C:\\Users\\Public\\spowerwk_dll.log", std::ios_base::app);
        if (ofs.is_open()) ofs << "[pre-pipe] " << msg << std::endl;
        return;
    }
    std::string packet = "LOG:" + msg + "\0";
    DWORD written;
    WriteFile(g_hPipe, packet.c_str(), (DWORD)packet.size(), &written, NULL);
}

// NtShutdownSystem
typedef enum _SHUTDOWN_ACTION {
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION;

extern "C" NTSYSAPI NTSTATUS NTAPI NtShutdownSystem(SHUTDOWN_ACTION Action);

// Global state
std::atomic<bool> g_isGhostMode{ false };

// -----------------------------------------------------------------------
// Ghost Mode power-button watcher
// After ghost mode is activated the normal shutdown code path (ShutdownWindowsWorkerThread)
// may no longer be called when the user presses the physical power button,
// because winlogon's state machine has already exited the shutdown flow.
// We register for ACPI / WM_POWERBROADCAST events on a hidden window and
// issue a hard reboot ourselves when we see the button.
// -----------------------------------------------------------------------
static HWND       g_hPowerWnd  = NULL;
static HPOWERNOTIFY g_hPowerNotify = NULL;
static const GUID GUID_POWERBUTTON_ACTION_FLAGS =
    { 0x013995e2, 0x1b44, 0x4b3a, { 0xb9, 0x23, 0xf4, 0x96, 0x61, 0xd4, 0x7c, 0x52 } };

void DoHardReboot() {
    LogToPipe("DoHardReboot: Acquiring SeShutdownPrivilege and calling NtShutdownSystem(Reboot).");
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
        CloseHandle(hToken);
    }
    NtShutdownSystem(ShutdownReboot);
}

LRESULT CALLBACK GhostPowerWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_POWERBROADCAST) {
        if (wParam == PBT_APMPOWERSTATUSCHANGE || wParam == PBT_APMRESUMEAUTOMATIC ||
            wParam == PBT_APMSUSPEND) {
            // Any power transition during ghost mode => reboot
            if (g_isGhostMode.load()) {
                LogToPipe("GhostPowerWndProc: WM_POWERBROADCAST during Ghost Mode. Rebooting.");
                DoHardReboot();
            }
        }
        if (wParam == PBT_POWERSETTINGCHANGE) {
            POWERBROADCAST_SETTING* pbs = reinterpret_cast<POWERBROADCAST_SETTING*>(lParam);
            if (pbs && IsEqualGUID(pbs->PowerSetting, GUID_POWERBUTTON_ACTION_FLAGS)) {
                if (g_isGhostMode.load()) {
                    LogToPipe("GhostPowerWndProc: GUID_POWERBUTTON_ACTION_FLAGS change during Ghost Mode. Rebooting.");
                    DoHardReboot();
                }
            }
        }
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

DWORD WINAPI GhostPowerWatcherThread(LPVOID) {
    LogToPipe("GhostPowerWatcherThread: Started.");

    // Register a hidden message-only window to receive WM_POWERBROADCAST
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = GhostPowerWndProc;
    wc.hInstance     = GetModuleHandleA(NULL);
    wc.lpszClassName = L"SpowerwkGhostPower";
    RegisterClassExW(&wc);

    g_hPowerWnd = CreateWindowExW(0, L"SpowerwkGhostPower", L"",
        0, 0, 0, 0, 0, HWND_MESSAGE, NULL, GetModuleHandleA(NULL), NULL);
    if (!g_hPowerWnd) {
        LogToPipe("GhostPowerWatcherThread: CreateWindowEx failed.");
        return 1;
    }

    // Register for power-button-specific setting changes
    g_hPowerNotify = RegisterPowerSettingNotification(
        g_hPowerWnd, &GUID_POWERBUTTON_ACTION_FLAGS, DEVICE_NOTIFY_WINDOW_HANDLE);

    LogToPipe("GhostPowerWatcherThread: Window created, entering message loop.");

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);

        // Also check: if ghost mode was cleared somehow, exit
        if (!g_isGhostMode.load()) break;
    }

    if (g_hPowerNotify) {
        UnregisterPowerSettingNotification(g_hPowerNotify);
        g_hPowerNotify = NULL;
    }
    if (g_hPowerWnd) {
        DestroyWindow(g_hPowerWnd);
        g_hPowerWnd = NULL;
    }
    LogToPipe("GhostPowerWatcherThread: Exiting.");
    return 0;
}

void StartGhostPowerWatcher() {
    HANDLE hT = CreateThread(NULL, 0, GhostPowerWatcherThread, NULL, 0, NULL);
    if (hT) CloseHandle(hT);
    else LogToPipe("StartGhostPowerWatcher: CreateThread failed.");
}

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
        LogToPipe("AskPythonServiceToBlockShutdown: Failed to write QUERY_SHUTDOWN to pipe.");
        return false;
    }

    char buf[16] = { 0 };
    DWORD bytesRead;
    if (ReadFile(g_hPipe, buf, sizeof(buf) - 1, &bytesRead, NULL)) {
        if (strcmp(buf, "BLOCK") == 0) {
            LogToPipe("AskPythonServiceToBlockShutdown: Received strict BLOCK from service.");
            return true;
        } else if (strcmp(buf, "ALLOW") == 0) {
            LogToPipe("AskPythonServiceToBlockShutdown: Received strict ALLOW from service.");
            return false;
        } else {
            LogToPipe(std::string("AskPythonServiceToBlockShutdown: Received unknown response: ") + buf);
        }
    } else {
        LogToPipe("AskPythonServiceToBlockShutdown: Failed to read response from pipe.");
    }
    
    // Fail-open: if service is unreachable or gives unknown response, allow shutdown.
    return false;
}

// Turn off the display from within winlogon's interactive session (Session 1).
// Calling this from the DLL is correct — service (Session 0) cannot reach
// Session 1 windows via HWND_BROADCAST due to session isolation.
void TurnOffDisplay() {
    LogToPipe("TurnOffDisplay: Sending SC_MONITORPOWER=2 to HWND_BROADCAST.");

    // Prevent OS from automatically waking the display back up
    SetThreadExecutionState(ES_CONTINUOUS);

    // WM_SYSCOMMAND / SC_MONITORPOWER / lParam=2 => power off
    // Use SendMessageTimeout so we don't block forever if a window is unresponsive
    DWORD_PTR result = 0;
    SendMessageTimeoutW(
        HWND_BROADCAST,
        WM_SYSCOMMAND,
        SC_MONITORPOWER,
        2,               // 2 = power off, 1 = low power, -1 = on
        SMTO_ABORTIFHUNG | SMTO_NOTIMEOUTIFNOTHUNG,
        2000,
        &result);

    // Also try the desktop window directly in case broadcast is filtered
    HWND hDesk = GetDesktopWindow();
    if (hDesk) {
        SendMessageTimeoutW(hDesk, WM_SYSCOMMAND, SC_MONITORPOWER, 2,
            SMTO_ABORTIFHUNG, 1000, &result);
    }

    LogToPipe("TurnOffDisplay: Done.");
}

// Hooked ShutdownWindowsWorkerThread
__declspec(guard(nocf))
void __fastcall Hooked_ShutdownWindowsWorkerThread(PTP_CALLBACK_INSTANCE Instance, PVOID Context) {
    if (g_isGhostMode.load()) {
        // This is a secondary call (e.g. ACPI power button pressed during ghost mode)
        // The ghost-power-watcher thread handles this via WM_POWERBROADCAST,
        // but if ShutdownWindowsWorkerThread is somehow reached again, reboot here too.
        LogToPipe("Hooked_ShutdownWindowsWorkerThread: Ghost mode active. Secondary call - hard reboot!");
        DoHardReboot();
        return;
    }

    LogToPipe("Hooked_ShutdownWindowsWorkerThread: Intercepted primary shutdown call. Querying Service...");
    if (AskPythonServiceToBlockShutdown()) {
        LogToPipe("Service replied BLOCK. Entering Ghost Mode and spoofing context.");
        g_isGhostMode.store(true);
        // Start dedicated power-button watcher so physical button press triggers reboot
        StartGhostPowerWatcher();
        // Turn off display from within Session 1 (winlogon context) — this actually works
        TurnOffDisplay();
        // Modify Context to force Logout (0) instead of Shutdown/Reboot
        Original_ShutdownWindowsWorkerThread(Instance, (PVOID)0);
    } else {
        LogToPipe("Service replied ALLOW. Permitting normal shutdown.");
        // Allow normal shutdown
        Original_ShutdownWindowsWorkerThread(Instance, Context);
    }
}

// Hooked WlDisplayStatusByResourceId
__declspec(guard(nocf))
__int64 __fastcall Hooked_WlDisplayStatusByResourceId(unsigned int a1, unsigned int a2, unsigned int a3, PVOID a4) {
    if (g_isGhostMode && a1 == 1003) {
        LogToPipe("Hooked_WlDisplayStatusByResourceId: Spoofing logout UI (1003) to shutdown UI (1204).");
        // If we are in ghost mode (forced logout) and it tries to display "Logging off" (1003)
        // We spoof it to "Shutting down" (1204)
        a1 = 1204;
    }
    return Original_WlDisplayStatusByResourceId(a1, a2, a3, a4);
}

// Original WlStateMachineSetSignal
typedef __int64(__fastcall* tWlStateMachineSetSignal)(unsigned int a1, PVOID a2);
tWlStateMachineSetSignal Original_WlStateMachineSetSignal = nullptr;

// Hooked WlStateMachineSetSignal
__declspec(guard(nocf))
__int64 __fastcall Hooked_WlStateMachineSetSignal(unsigned int a1, PVOID a2) {
    if (g_isGhostMode.load() && a1 == 3 && a2 == nullptr) {
        LogToPipe("Hooked_WlStateMachineSetSignal: Intercepted SAS (Ctrl+Alt+Del) signal in Ghost Mode. Blocking.");
        return 13;
    }
    return Original_WlStateMachineSetSignal(a1, a2);
}

// Initialization Thread
DWORD WINAPI InitThread(LPVOID lpParam) {
    LogToFile("InitThread: Started.");

    // 1. Connect to named pipe created by Python service
    LogToFile("InitThread: Entering pipe connect loop.");
    while (true) {
        g_hPipe = CreateFileA("\\\\.\\pipe\\spowerwk_ipc", GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);
        if (g_hPipe != INVALID_HANDLE_VALUE) {
            break;
        }
        Sleep(1000);
    }
    LogToFile("InitThread: Pipe connected. Sending log via pipe.");

    LogToPipe("InitThread: Connected to IPC pipe.");
    LogToFile("InitThread: Log sent via pipe. Waiting for RVA message.");

    // 2. Python service will send RVAs once connected
    char buf[128] = { 0 };
    DWORD bytesRead;
    if (!ReadFile(g_hPipe, buf, sizeof(buf) - 1, &bytesRead, NULL)) {
        LogToFile("InitThread: ReadFile for RVA FAILED. err=" + std::to_string(GetLastError()));
        LogToPipe("InitThread: Failed to read RVA message from pipe.");
        CloseHandle(g_hPipe);
        return 0;
    }
    LogToFile("InitThread: ReadFile for RVA succeeded. bytes=" + std::to_string(bytesRead));

    std::string msg(buf);
    LogToPipe("InitThread: Received RVAs: " + msg);
    LogToFile("InitThread: RVA msg=" + msg);

    if (msg.rfind("RVA:", 0) != 0) {
        LogToFile("InitThread: Invalid RVA format, aborting.");
        LogToPipe("InitThread: Invalid RVA format.");
        CloseHandle(g_hPipe);
        return 0;
    }

    size_t firstColon = msg.find(':');
    size_t secondColon = msg.find(':', firstColon + 1);
    size_t thirdColon = msg.find(':', secondColon + 1);

    if (firstColon == std::string::npos || secondColon == std::string::npos || thirdColon == std::string::npos) {
        LogToFile("InitThread: Colon parse failed.");
        CloseHandle(g_hPipe);
        return 0;
    }

    std::string shutdownRvaStr = msg.substr(firstColon + 1, secondColon - firstColon - 1);
    std::string displayRvaStr  = msg.substr(secondColon + 1, thirdColon - secondColon - 1);
    std::string sasRvaStr      = msg.substr(thirdColon + 1);
    // strip null terminator if present
    if (!sasRvaStr.empty() && sasRvaStr.back() == '\0') sasRvaStr.pop_back();

    LogToFile("InitThread: shutdownRvaStr=" + shutdownRvaStr + " displayRvaStr=" + displayRvaStr + " sasRvaStr=" + sasRvaStr);

    uint64_t shutdownRva = std::stoull(shutdownRvaStr, nullptr, 16);
    uint64_t displayRva  = std::stoull(displayRvaStr,  nullptr, 16);
    uint64_t sasRva      = std::stoull(sasRvaStr,      nullptr, 16);

    HMODULE hModule = GetModuleHandleA(NULL);
    if (!hModule) {
        LogToFile("InitThread: GetModuleHandleA returned NULL.");
        LogToPipe("InitThread: GetModuleHandleA returned NULL.");
        CloseHandle(g_hPipe);
        return 0;
    }

    void* targetShutdown = (void*)((uintptr_t)hModule + shutdownRva);
    void* targetDisplay  = (void*)((uintptr_t)hModule + displayRva);
    void* targetSas      = (void*)((uintptr_t)hModule + sasRva);

    LogToFile("InitThread: base=" + std::to_string((uintptr_t)hModule)
        + " targetShutdown=" + std::to_string((uintptr_t)targetShutdown)
        + " targetDisplay="  + std::to_string((uintptr_t)targetDisplay)
        + " targetSas="      + std::to_string((uintptr_t)targetSas));
    LogToPipe("InitThread: Target Shutdown Address: " + std::to_string((uintptr_t)targetShutdown));

    // 3. MH_Initialize
    LogToFile("InitThread: Calling MH_Initialize...");
    MH_STATUS mhInit = MH_Initialize();
    LogToFile("InitThread: MH_Initialize returned " + std::to_string((int)mhInit));
    if (mhInit != MH_OK) {
        LogToPipe("InitThread: MH_Initialize failed.");
        CloseHandle(g_hPipe);
        return 0;
    }
    LogToPipe("InitThread: MH_Initialize success.");

    // MH_CreateHook - Shutdown
    if (shutdownRva != 0) {
        LogToFile("InitThread: Calling MH_CreateHook for ShutdownWindowsWorkerThread...");
        MH_STATUS s = MH_CreateHook(targetShutdown,
            &Hooked_ShutdownWindowsWorkerThread,
            reinterpret_cast<LPVOID*>(&Original_ShutdownWindowsWorkerThread));
        LogToFile("InitThread: MH_CreateHook Shutdown returned " + std::to_string((int)s));
        if (s == MH_OK) LogToPipe("InitThread: MH_CreateHook for ShutdownWindowsWorkerThread success.");
        else            LogToPipe("InitThread: MH_CreateHook for ShutdownWindowsWorkerThread failed err=" + std::to_string((int)s));
    } else {
        LogToFile("InitThread: shutdownRva is 0, skipping hook.");
        LogToPipe("InitThread: shutdownRva is 0, skipping hook.");
    }

    // MH_CreateHook - Display
    if (displayRva != 0) {
        LogToFile("InitThread: Calling MH_CreateHook for WlDisplayStatusByResourceId...");
        MH_STATUS s = MH_CreateHook(targetDisplay,
            &Hooked_WlDisplayStatusByResourceId,
            reinterpret_cast<LPVOID*>(&Original_WlDisplayStatusByResourceId));
        LogToFile("InitThread: MH_CreateHook Display returned " + std::to_string((int)s));
        if (s == MH_OK) LogToPipe("InitThread: MH_CreateHook for WlDisplayStatusByResourceId success.");
        else            LogToPipe("InitThread: MH_CreateHook for WlDisplayStatusByResourceId failed err=" + std::to_string((int)s));
    }

    // MH_CreateHook - SAS
    if (sasRva != 0) {
        LogToFile("InitThread: Calling MH_CreateHook for WlStateMachineSetSignal...");
        MH_STATUS s = MH_CreateHook(targetSas,
            &Hooked_WlStateMachineSetSignal,
            reinterpret_cast<LPVOID*>(&Original_WlStateMachineSetSignal));
        LogToFile("InitThread: MH_CreateHook SAS returned " + std::to_string((int)s));
        if (s == MH_OK) LogToPipe("InitThread: MH_CreateHook for WlStateMachineSetSignal success.");
        else            LogToPipe("InitThread: MH_CreateHook for WlStateMachineSetSignal failed err=" + std::to_string((int)s));
    }

    // --- CFG fix ---
    LogToFile("InitThread: Starting CFG registration...");
    {
        HANDLE hProcess = GetCurrentProcess();
        auto RegisterPageAsCfgValid = [&](void* addr) {
            if (!addr) return;
            typedef BOOL (WINAPI *pSetProcessValidCallTargets)(HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO);
            static pSetProcessValidCallTargets fnSetProcessValidCallTargets =
                (pSetProcessValidCallTargets)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetProcessValidCallTargets");
            if (!fnSetProcessValidCallTargets) return;

            ULONG_PTR base = (ULONG_PTR)addr & ~(ULONG_PTR)(0xFFF);
            const ULONG_PTR pageSize = 0x1000;
            const ULONG nSlots = (ULONG)(pageSize / 16);
            CFG_CALL_TARGET_INFO* entries = new CFG_CALL_TARGET_INFO[nSlots];
            for (ULONG i = 0; i < nSlots; i++) {
                entries[i].Offset = i * 16;
                entries[i].Flags  = CFG_CALL_TARGET_VALID;
            }
            BOOL ok = fnSetProcessValidCallTargets(hProcess, (PVOID)base, pageSize, nSlots, entries);
            delete[] entries;
            DWORD err = GetLastError();
            LogToFile("InitThread: CFG register addr=" + std::to_string((uintptr_t)addr)
                + " base=" + std::to_string(base) + " ok=" + std::to_string(ok)
                + " err=" + std::to_string(err));
            if (!ok) LogToPipe("InitThread: SetProcessValidCallTargets failed err=" + std::to_string(err));
            else     LogToPipe("InitThread: CFG page registered base=" + std::to_string(base));
        };

        RegisterPageAsCfgValid((void*)Original_ShutdownWindowsWorkerThread);
        RegisterPageAsCfgValid((void*)Original_WlDisplayStatusByResourceId);
        RegisterPageAsCfgValid((void*)Original_WlStateMachineSetSignal);
        RegisterPageAsCfgValid((void*)&Hooked_ShutdownWindowsWorkerThread);
        RegisterPageAsCfgValid((void*)&Hooked_WlDisplayStatusByResourceId);
        RegisterPageAsCfgValid((void*)&Hooked_WlStateMachineSetSignal);
    }
    LogToFile("InitThread: CFG registration done. Calling MH_EnableHook...");
    LogToPipe("InitThread: CFG registration complete.");

    MH_STATUS enSt = MH_EnableHook(MH_ALL_HOOKS);
    LogToFile("InitThread: MH_EnableHook returned " + std::to_string((int)enSt));
    LogToPipe("InitThread: All hooks enabled (status=" + std::to_string((int)enSt) + "). DLL init complete.");

    LogToFile("InitThread: Entering heartbeat loop.");

    // 4. Heartbeat loop
    while (true) {
        DWORD bytesWritten;
        const char* beat = "PING\0";
        if (!WriteFile(g_hPipe, beat, strlen(beat) + 1, &bytesWritten, NULL)) {
            LogToFile("InitThread: Heartbeat WriteFile failed, pipe broken.");
            break;
        }
        Sleep(5000);
    }

    LogToFile("InitThread: Exiting. Cleaning up hooks.");
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    CloseHandle(g_hPipe);
    g_hPipe = INVALID_HANDLE_VALUE;
    FreeLibraryAndExitThread((HMODULE)lpParam, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        LogToFile("DllMain: DLL_PROCESS_ATTACH. hModule=" + std::to_string((uintptr_t)hModule));
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(NULL, 0, InitThread, hModule, 0, NULL);
        if (hThread) {
            LogToFile("DllMain: CreateThread succeeded. hThread=" + std::to_string((uintptr_t)hThread));
            CloseHandle(hThread);
        } else {
            LogToFile("DllMain: CreateThread FAILED. err=" + std::to_string(GetLastError()));
        }
        LogToFile("DllMain: Returning TRUE.");
    }
    return TRUE;
}
