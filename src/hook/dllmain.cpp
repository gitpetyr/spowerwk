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

// ── File log (init only; pipe unavailable during DLL attach) ─────────────────
void LogToFile(const std::string& msg) {
    std::ofstream ofs("C:\\Users\\Public\\spowerwk_dll.log", std::ios_base::app);
    if (ofs.is_open()) ofs << msg << std::endl;
}

// ── Pipe globals ──────────────────────────────────────────────────────────────
//
// g_hPipe is written exclusively by InitThread and read by hook callbacks.
// std::atomic<HANDLE> gives safe publication on x64 (pointer-sized load/store).
//
// g_pipeMutex serialises ALL pipe I/O so LOG: messages and the QUERY_SHUTDOWN
// request-response pair never interleave at the byte level on the same handle.
// AskPythonServiceToBlockShutdown acquires the mutex for the full exchange and
// does NOT call LogToPipe while holding it, to avoid recursive locking.

std::atomic<HANDLE> g_hPipe{ INVALID_HANDLE_VALUE };
std::mutex          g_pipeMutex;

// PipeWrite / PipeRead ─────────────────────────────────────────────────────────
// Callers MUST hold g_pipeMutex.
// FILE_FLAG_OVERLAPPED lets us enforce a real deadline so a stalled Python
// service cannot block a thread-pool callback (Hooked_ShutdownWindowsWorkerThread)
// indefinitely and wedge the entire winlogon thread pool.

static bool PipeWrite(const char* buf, DWORD len, DWORD timeoutMs = 5000) {
    HANDLE h = g_hPipe.load(std::memory_order_acquire);
    if (h == INVALID_HANDLE_VALUE) return false;
    HANDLE hEv = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hEv) return false;
    OVERLAPPED ov = {};
    ov.hEvent = hEv;
    DWORD written = 0;
    bool ok = false;
    if (WriteFile(h, buf, len, NULL, &ov)) {
        ok = GetOverlappedResult(h, &ov, &written, FALSE) && written == len;
    } else if (GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(hEv, timeoutMs) == WAIT_OBJECT_0)
            ok = GetOverlappedResult(h, &ov, &written, FALSE) && written == len;
        else { CancelIo(h); GetOverlappedResult(h, &ov, &written, TRUE); }
    }
    CloseHandle(hEv);
    return ok;
}

static bool PipeRead(char* buf, DWORD len, DWORD* pRead, DWORD timeoutMs = 5000) {
    HANDLE h = g_hPipe.load(std::memory_order_acquire);
    if (h == INVALID_HANDLE_VALUE) return false;
    HANDLE hEv = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hEv) return false;
    OVERLAPPED ov = {};
    ov.hEvent = hEv;
    DWORD read = 0;
    bool ok = false;
    if (ReadFile(h, buf, len, NULL, &ov)) {
        ok = GetOverlappedResult(h, &ov, &read, FALSE);
        if (ok && pRead) *pRead = read;
    } else if (GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(hEv, timeoutMs) == WAIT_OBJECT_0) {
            ok = GetOverlappedResult(h, &ov, &read, FALSE);
            if (ok && pRead) *pRead = read;
        } else { CancelIo(h); GetOverlappedResult(h, &ov, &read, TRUE); }
    }
    CloseHandle(hEv);
    return ok;
}

// LogToPipe acquires g_pipeMutex independently; it must NOT be called by any
// code that already holds g_pipeMutex (see AskPythonServiceToBlockShutdown).
void LogToPipe(const std::string& msg) {
    if (g_hPipe.load(std::memory_order_acquire) == INVALID_HANDLE_VALUE) {
        LogToFile("[pre-pipe] " + msg);
        return;
    }
    std::string packet = "LOG:" + msg + '\0';
    std::lock_guard<std::mutex> lock(g_pipeMutex);
    PipeWrite(packet.c_str(), (DWORD)packet.size(), 2000);
}

// ── NtShutdownSystem ──────────────────────────────────────────────────────────
typedef enum _SHUTDOWN_ACTION {
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION;
extern "C" NTSYSAPI NTSTATUS NTAPI NtShutdownSystem(SHUTDOWN_ACTION Action);

// ── Global state ──────────────────────────────────────────────────────────────
std::atomic<bool> g_isGhostMode{ false };

// ── Ghost-mode power-button watcher ──────────────────────────────────────────
static HWND         g_hPowerWnd    = NULL;
static HPOWERNOTIFY g_hPowerNotify = NULL;
static const GUID   GUID_POWERBUTTON_ACTION_FLAGS =
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
    g_hPowerNotify = RegisterPowerSettingNotification(
        g_hPowerWnd, &GUID_POWERBUTTON_ACTION_FLAGS, DEVICE_NOTIFY_WINDOW_HANDLE);
    LogToPipe("GhostPowerWatcherThread: Window created, entering message loop.");
    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    if (g_hPowerNotify) { UnregisterPowerSettingNotification(g_hPowerNotify); g_hPowerNotify = NULL; }
    if (g_hPowerWnd)    { DestroyWindow(g_hPowerWnd); g_hPowerWnd = NULL; }
    LogToPipe("GhostPowerWatcherThread: Exiting.");
    return 0;
}

void StartGhostPowerWatcher() {
    HANDLE hT = CreateThread(NULL, 0, GhostPowerWatcherThread, NULL, 0, NULL);
    if (hT) CloseHandle(hT);
    else LogToPipe("StartGhostPowerWatcher: CreateThread failed.");
}

void TurnOffDisplay(); // forward declaration — defined below after hook originals

// ── Ghost-mode display keeper ─────────────────────────────────────────────────
// SC_MONITORPOWER is a one-shot command. After logout, the Winlogon login UI
// repaints the screen and may wake the display. This thread re-issues the
// power-off command every DISPLAY_KEEPER_INTERVAL_MS while Ghost Mode is active.
//
// Critical: this thread must NEVER create any USER objects (windows, menus…).
// SetThreadDesktop (called inside TurnOffDisplay) fails if the calling thread
// already owns windows. Keeping this thread window-free guarantees the desktop
// switch works on every iteration.

static const DWORD DISPLAY_KEEPER_INITIAL_DELAY_MS  = 2000;  // wait for logout transition
static const DWORD DISPLAY_KEEPER_INTERVAL_MS       = 10000; // re-send period

DWORD WINAPI GhostDisplayKeeperThread(LPVOID) {
    LogToPipe("GhostDisplayKeeperThread: Started. Initial delay before first re-send.");
    Sleep(DISPLAY_KEEPER_INITIAL_DELAY_MS);
    while (g_isGhostMode.load()) {
        TurnOffDisplay();
        Sleep(DISPLAY_KEEPER_INTERVAL_MS);
    }
    LogToPipe("GhostDisplayKeeperThread: Ghost mode cleared, exiting.");
    return 0;
}

void StartGhostDisplayKeeper() {
    HANDLE hT = CreateThread(NULL, 0, GhostDisplayKeeperThread, NULL, 0, NULL);
    if (hT) CloseHandle(hT);
    else LogToPipe("StartGhostDisplayKeeper: CreateThread failed.");
}

// ── Hook originals ────────────────────────────────────────────────────────────
typedef void(__fastcall* tShutdownWindowsWorkerThread)(PTP_CALLBACK_INSTANCE Instance, PVOID Context);
tShutdownWindowsWorkerThread Original_ShutdownWindowsWorkerThread = nullptr;

typedef __int64(__fastcall* tWlDisplayStatusByResourceId)(unsigned int a1, unsigned int a2, unsigned int a3, PVOID a4);
tWlDisplayStatusByResourceId Original_WlDisplayStatusByResourceId = nullptr;

typedef __int64(__fastcall* tWlStateMachineSetSignal)(unsigned int a1, PVOID a2);
tWlStateMachineSetSignal Original_WlStateMachineSetSignal = nullptr;

// ── Shutdown policy query ─────────────────────────────────────────────────────
// Holds g_pipeMutex for the full write→read round-trip so LOG: messages cannot
// interleave with the response bytes. Does NOT call LogToPipe while locked.
bool AskPythonServiceToBlockShutdown() {
    if (g_hPipe.load(std::memory_order_acquire) == INVALID_HANDLE_VALUE) return false;

    bool success = false;
    bool block   = false;
    char resp[16] = {};

    {
        std::lock_guard<std::mutex> lock(g_pipeMutex);
        const char* req = "QUERY_SHUTDOWN\0";
        if (PipeWrite(req, (DWORD)(strlen(req) + 1), 3000)) {
            DWORD bytesRead = 0;
            success = PipeRead(resp, sizeof(resp) - 1, &bytesRead, 6000);
            if (success) block = (strcmp(resp, "BLOCK") == 0);
        }
    }

    // Log after releasing the mutex so LogToPipe can acquire it safely
    if (!success) {
        LogToPipe("AskPythonServiceToBlockShutdown: pipe timeout/error, fail-open.");
        return false;
    }
    if (block) {
        LogToPipe("AskPythonServiceToBlockShutdown: received BLOCK.");
        return true;
    }
    LogToPipe(std::string("AskPythonServiceToBlockShutdown: received '") + resp + "', permitting.");
    return false;
}

// ── TurnOffDisplay ─────────────────────────────────────────────────────────────
// winlogon.exe already runs inside WinSta0; SetProcessWindowStation must NOT
// be called here because it is process-wide and would corrupt the window-station
// state of every other winlogon thread (clipboard chain, class atoms, USER
// handle tables are all window-station-scoped).
// SetThreadDesktop is thread-local and safe to call from inside winlogon.
void TurnOffDisplay() {
    LogToPipe("TurnOffDisplay: Switching thread desktop to Winlogon and sending SC_MONITORPOWER=2.");

    // Prevent the OS from immediately waking the display
    SetThreadExecutionState(ES_CONTINUOUS);

    // Save the current thread desktop so we can restore it afterwards
    HDESK hOriginalDesktop = GetThreadDesktop(GetCurrentThreadId());

    // winlogon.exe is already associated with WinSta0, so OpenDesktopW resolves
    // the "Winlogon" desktop within the process window station directly.
    HDESK hDesk = OpenDesktopW(L"Winlogon", 0, FALSE, MAXIMUM_ALLOWED);
    if (!hDesk) {
        LogToPipe("TurnOffDisplay: OpenDesktopW(Winlogon) failed. Error: " + std::to_string(GetLastError()));
        return;
    }

    if (SetThreadDesktop(hDesk)) {
        LogToPipe("TurnOffDisplay: On Winlogon desktop. Broadcasting SC_MONITORPOWER=2...");
        DWORD_PTR result = 0;
        SendMessageTimeoutW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2,
            SMTO_ABORTIFHUNG | SMTO_NOTIMEOUTIFNOTHUNG, 2000, &result);
        HWND hDesktopWnd = GetDesktopWindow();
        if (hDesktopWnd)
            SendMessageTimeoutW(hDesktopWnd, WM_SYSCOMMAND, SC_MONITORPOWER, 2,
                SMTO_ABORTIFHUNG, 1000, &result);
        SetThreadDesktop(hOriginalDesktop);
    } else {
        LogToPipe("TurnOffDisplay: SetThreadDesktop failed. Error: " + std::to_string(GetLastError()));
    }
    CloseDesktop(hDesk);
    LogToPipe("TurnOffDisplay: Done.");
}

// ── Hooked functions ──────────────────────────────────────────────────────────
__declspec(guard(nocf))
void __fastcall Hooked_ShutdownWindowsWorkerThread(PTP_CALLBACK_INSTANCE Instance, PVOID Context) {
    if (g_isGhostMode.load()) {
        LogToPipe("Hooked_ShutdownWindowsWorkerThread: Ghost mode active. Secondary call - hard reboot!");
        DoHardReboot();
        return;
    }
    LogToPipe("Hooked_ShutdownWindowsWorkerThread: Intercepted primary shutdown call. Querying Service...");
    if (AskPythonServiceToBlockShutdown()) {
        LogToPipe("Service replied BLOCK. Entering Ghost Mode and spoofing context.");
        g_isGhostMode.store(true);
        StartGhostPowerWatcher();
        StartGhostDisplayKeeper();
        TurnOffDisplay();
        Original_ShutdownWindowsWorkerThread(Instance, (PVOID)0);
    } else {
        LogToPipe("Service replied ALLOW. Permitting normal shutdown.");
        Original_ShutdownWindowsWorkerThread(Instance, Context);
    }
}

__declspec(guard(nocf))
__int64 __fastcall Hooked_WlDisplayStatusByResourceId(unsigned int a1, unsigned int a2, unsigned int a3, PVOID a4) {
    if (g_isGhostMode.load() && a1 == 1003) {
        LogToPipe("Hooked_WlDisplayStatusByResourceId: Spoofing logout UI (1003) to shutdown UI (1204).");
        a1 = 1204;
    }
    return Original_WlDisplayStatusByResourceId(a1, a2, a3, a4);
}

__declspec(guard(nocf))
__int64 __fastcall Hooked_WlStateMachineSetSignal(unsigned int a1, PVOID a2) {
    if (g_isGhostMode.load() && a1 == 3 && a2 == nullptr) {
        LogToPipe("Hooked_WlStateMachineSetSignal: Intercepted SAS (Ctrl+Alt+Del) signal in Ghost Mode. Blocking.");
        return 13;
    }
    return Original_WlStateMachineSetSignal(a1, a2);
}

// ── InitThread: connect → handshake → heartbeat, reconnects forever ───────────
//
// The DLL is NEVER unloaded after injection. FreeLibraryAndExitThread would
// unmap the DLL's code pages while hook trampolines may still be executing in
// other winlogon threads, causing an immediate BSOD (access violation in a
// critical system process).
//
// Instead, InitThread loops: on pipe disconnection it closes the old handle,
// waits for the service to restart, and reconnects. Hooks are installed only
// on the first successful connection; subsequent connections discard the RVA
// message (the service always sends it) and proceed straight to heartbeat.

DWORD WINAPI InitThread(LPVOID /*lpParam*/) {
    LogToFile("InitThread: Started.");
    bool hooksInstalled = false;

    for (;;) {

        // ── Phase 1: Connect ───────────────────────────────────────────────────
        LogToFile("InitThread: Entering pipe connect loop.");
        for (;;) {
            HANDLE h = CreateFileA("\\\\.\\pipe\\spowerwk_ipc",
                GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                g_hPipe.store(h, std::memory_order_release);
                break;
            }
            Sleep(1000);
        }
        LogToFile("InitThread: Pipe connected.");
        LogToPipe("InitThread: Connected to IPC pipe.");

        // ── Phase 2: RVA handshake & hook installation ─────────────────────────
        bool phaseOk = true;
        if (!hooksInstalled) {
            char buf[128] = {};
            DWORD bytesRead = 0;
            bool readOk = false;
            {
                std::lock_guard<std::mutex> lock(g_pipeMutex);
                readOk = PipeRead(buf, sizeof(buf) - 1, &bytesRead, 15000);
            }
            if (!readOk) {
                LogToFile("InitThread: PipeRead for RVA timed out or failed. err=" + std::to_string(GetLastError()));
                LogToPipe("InitThread: Failed to read RVA message from pipe.");
                phaseOk = false;
            } else {
                std::string msg(buf);
                LogToPipe("InitThread: Received RVAs: " + msg);
                LogToFile("InitThread: RVA msg=" + msg);

                if (msg.rfind("RVA:", 0) != 0) {
                    LogToFile("InitThread: Invalid RVA format, aborting phase.");
                    phaseOk = false;
                } else {
                    size_t c1 = msg.find(':');
                    size_t c2 = msg.find(':', c1 + 1);
                    size_t c3 = msg.find(':', c2 + 1);

                    if (c1 == std::string::npos || c2 == std::string::npos || c3 == std::string::npos) {
                        LogToFile("InitThread: Colon parse failed.");
                        phaseOk = false;
                    } else {
                        std::string shutdownRvaStr = msg.substr(c1 + 1, c2 - c1 - 1);
                        std::string displayRvaStr  = msg.substr(c2 + 1, c3 - c2 - 1);
                        std::string sasRvaStr      = msg.substr(c3 + 1);
                        if (!sasRvaStr.empty() && sasRvaStr.back() == '\0') sasRvaStr.pop_back();

                        LogToFile("InitThread: shutdownRva=" + shutdownRvaStr
                            + " displayRva=" + displayRvaStr + " sasRva=" + sasRvaStr);

                        uint64_t shutdownRva = std::stoull(shutdownRvaStr, nullptr, 16);
                        uint64_t displayRva  = std::stoull(displayRvaStr,  nullptr, 16);
                        uint64_t sasRva      = std::stoull(sasRvaStr,      nullptr, 16);

                        HMODULE hMod = GetModuleHandleA(NULL);
                        if (!hMod) {
                            LogToFile("InitThread: GetModuleHandleA returned NULL.");
                            LogToPipe("InitThread: GetModuleHandleA returned NULL.");
                            phaseOk = false;
                        }

                        if (phaseOk) {
                            void* tShutdown = (void*)((uintptr_t)hMod + shutdownRva);
                            void* tDisplay  = (void*)((uintptr_t)hMod + displayRva);
                            void* tSas      = (void*)((uintptr_t)hMod + sasRva);

                            LogToFile("InitThread: Calling MH_Initialize...");
                            MH_STATUS mhInit = MH_Initialize();
                            LogToFile("InitThread: MH_Initialize=" + std::to_string((int)mhInit));
                            if (mhInit != MH_OK) {
                                LogToPipe("InitThread: MH_Initialize failed.");
                                phaseOk = false;
                            } else {
                                LogToPipe("InitThread: MH_Initialize success.");

                                if (shutdownRva != 0) {
                                    MH_STATUS s = MH_CreateHook(tShutdown,
                                        &Hooked_ShutdownWindowsWorkerThread,
                                        reinterpret_cast<LPVOID*>(&Original_ShutdownWindowsWorkerThread));
                                    LogToPipe("InitThread: MH_CreateHook Shutdown=" + std::to_string((int)s));
                                } else {
                                    LogToPipe("InitThread: shutdownRva=0, skipping hook.");
                                }
                                if (displayRva != 0) {
                                    MH_STATUS s = MH_CreateHook(tDisplay,
                                        &Hooked_WlDisplayStatusByResourceId,
                                        reinterpret_cast<LPVOID*>(&Original_WlDisplayStatusByResourceId));
                                    LogToPipe("InitThread: MH_CreateHook Display=" + std::to_string((int)s));
                                }
                                if (sasRva != 0) {
                                    MH_STATUS s = MH_CreateHook(tSas,
                                        &Hooked_WlStateMachineSetSignal,
                                        reinterpret_cast<LPVOID*>(&Original_WlStateMachineSetSignal));
                                    LogToPipe("InitThread: MH_CreateHook SAS=" + std::to_string((int)s));
                                }

                                // CFG: register hook stubs and trampolines as valid call targets
                                LogToFile("InitThread: Starting CFG registration...");
                                {
                                    typedef BOOL (WINAPI *pSPVCT)(HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO);
                                    static pSPVCT fnSPVCT = (pSPVCT)GetProcAddress(
                                        GetModuleHandleA("kernel32.dll"), "SetProcessValidCallTargets");
                                    auto RegPage = [&](void* addr) {
                                        if (!addr || !fnSPVCT) return;
                                        ULONG_PTR base = (ULONG_PTR)addr & ~(ULONG_PTR)0xFFF;
                                        const ULONG nSlots = 0x1000 / 16;
                                        CFG_CALL_TARGET_INFO* e = new CFG_CALL_TARGET_INFO[nSlots];
                                        for (ULONG i = 0; i < nSlots; i++) {
                                            e[i].Offset = i * 16;
                                            e[i].Flags  = CFG_CALL_TARGET_VALID;
                                        }
                                        BOOL ok = fnSPVCT(GetCurrentProcess(), (PVOID)base, 0x1000, nSlots, e);
                                        delete[] e;
                                        if (!ok) LogToPipe("InitThread: CFG register failed addr="
                                            + std::to_string((uintptr_t)addr)
                                            + " err=" + std::to_string(GetLastError()));
                                        else LogToPipe("InitThread: CFG page registered base="
                                            + std::to_string(base));
                                    };
                                    RegPage((void*)Original_ShutdownWindowsWorkerThread);
                                    RegPage((void*)Original_WlDisplayStatusByResourceId);
                                    RegPage((void*)Original_WlStateMachineSetSignal);
                                    RegPage((void*)&Hooked_ShutdownWindowsWorkerThread);
                                    RegPage((void*)&Hooked_WlDisplayStatusByResourceId);
                                    RegPage((void*)&Hooked_WlStateMachineSetSignal);
                                }
                                LogToFile("InitThread: CFG registration done.");

                                MH_STATUS enSt = MH_EnableHook(MH_ALL_HOOKS);
                                LogToFile("InitThread: MH_EnableHook=" + std::to_string((int)enSt));
                                LogToPipe("InitThread: All hooks enabled (status=" + std::to_string((int)enSt)
                                    + "). DLL init complete.");
                                hooksInstalled = true;
                            }
                        }
                    }
                }
            }
        } else {
            // Subsequent connections: consume the RVA message the service always
            // sends on connect, then proceed to heartbeat with hooks already live.
            char discard[128] = {};
            DWORD dr = 0;
            {
                std::lock_guard<std::mutex> lock(g_pipeMutex);
                PipeRead(discard, sizeof(discard) - 1, &dr, 10000);
            }
            LogToPipe("InitThread: Reconnected. Hooks already active, discarding RVA message.");
        }

        // ── Phase 3: Heartbeat ─────────────────────────────────────────────────
        if (phaseOk) {
            LogToFile("InitThread: Entering heartbeat loop.");
            for (;;) {
                Sleep(5000);
                std::lock_guard<std::mutex> lock(g_pipeMutex);
                if (!PipeWrite("PING\0", 5, 3000)) {
                    LogToFile("InitThread: Heartbeat failed, pipe broken.");
                    break;
                }
            }
        }

        // ── Cleanup before reconnect ───────────────────────────────────────────
        {
            HANDLE h = g_hPipe.load(std::memory_order_acquire);
            g_hPipe.store(INVALID_HANDLE_VALUE, std::memory_order_release);
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        }
        LogToFile("InitThread: Pipe closed. Will reconnect.");
        Sleep(1000);

    } // for(;;) — never exits; DLL remains loaded to keep hooks alive
    return 0;
}

// ── DllMain ───────────────────────────────────────────────────────────────────
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        // Defer ALL work to a worker thread; the only safe operations under the
        // loader lock are those explicitly listed in the Windows DLL documentation.
        // In particular, do NOT call LogToFile here: std::ofstream touches the CRT
        // heap which acquires internal locks that can deadlock under the loader lock.
        HANDLE hThread = CreateThread(NULL, 0, InitThread, hModule, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
