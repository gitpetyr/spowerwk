// Inject to winlogon.exe
#include <windows.h>
#include <MinHook.h>
#include <string>
#include <winternl.h>
#include <fstream>

// ── File log (init only; pipe unavailable during DLL attach) ─────────────────
void LogToFile(const std::string& msg) {
    std::ofstream ofs("C:\\Users\\Public\\spowerwk_dll.log", std::ios_base::app);
    if (ofs.is_open()) ofs << msg << std::endl;
}

// ── Pipe globals ──────────────────────────────────────────────────────────────
//
// g_pipeLock is SRWLOCK_INIT ({0}) — a compile-time constant, zero initialised
// by the linker.  No constructor runs; safe in injected-DLL contexts where
// _DllMainCRTStartup may not execute.
//
// g_hPipe is ALWAYS accessed under g_pipeLock (exclusive).

static SRWLOCK g_pipeLock = SRWLOCK_INIT;
static HANDLE  g_hPipe    = INVALID_HANDLE_VALUE;

// Thin RAII guard — constructed only from worker threads, never from static init.
struct PipeLock {
    PipeLock()  { AcquireSRWLockExclusive(&g_pipeLock); }
    ~PipeLock() { ReleaseSRWLockExclusive(&g_pipeLock); }
    PipeLock(const PipeLock&)            = delete;
    PipeLock& operator=(const PipeLock&) = delete;
};

// PipeWrite / PipeRead ─────────────────────────────────────────────────────────
// Callers MUST hold g_pipeLock.
static bool PipeWrite(const char* buf, DWORD len) {
    if (g_hPipe == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    return WriteFile(g_hPipe, buf, len, &written, NULL) && written == len;
}

static bool PipeRead(char* buf, DWORD len, DWORD* pRead) {
    if (g_hPipe == INVALID_HANDLE_VALUE) return false;
    DWORD read = 0;
    BOOL ok = ReadFile(g_hPipe, buf, len, &read, NULL);
    if (ok && pRead) *pRead = read;
    return ok != FALSE;
}

// LogToPipe — acquires g_pipeLock; must NOT be called by code that already
// holds g_pipeLock (see AskPythonServiceToBlockShutdown).
void LogToPipe(const std::string& msg) {
    {
        PipeLock lk;
        if (g_hPipe != INVALID_HANDLE_VALUE) {
            std::string packet = "LOG:" + msg + '\0';
            PipeWrite(packet.c_str(), (DWORD)packet.size());
            return;
        }
    }
    LogToFile("[pre-pipe] " + msg);
}


// ── Hook originals ────────────────────────────────────────────────────────────
typedef void(__fastcall* tShutdownWindowsWorkerThread)(PTP_CALLBACK_INSTANCE Instance, PVOID Context);
tShutdownWindowsWorkerThread Original_ShutdownWindowsWorkerThread = nullptr;


// ── Shutdown policy query ─────────────────────────────────────────────────────
// Holds g_pipeLock for the full write→read round-trip so LOG: messages cannot
// interleave with the response bytes. Does NOT call LogToPipe while locked.
bool AskPythonServiceToBlockShutdown() {
    bool success = false;
    bool block   = false;
    char resp[16] = {};

    {
        PipeLock lk;
        if (g_hPipe == INVALID_HANDLE_VALUE) return false;
        const char* req = "QUERY_SHUTDOWN\0";
        if (PipeWrite(req, (DWORD)(strlen(req) + 1))) {
            DWORD bytesRead = 0;
            success = PipeRead(resp, sizeof(resp) - 1, &bytesRead);
            if (success) block = (strcmp(resp, "BLOCK") == 0);
        }
    }

    // Log after releasing the lock so LogToPipe can acquire it safely
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


// ── Hooked functions ──────────────────────────────────────────────────────────
__declspec(guard(nocf))
void __fastcall Hooked_ShutdownWindowsWorkerThread(PTP_CALLBACK_INSTANCE Instance, PVOID Context) {
    LogToPipe("Hooked_ShutdownWindowsWorkerThread: Intercepted shutdown call. Querying Service...");
    if (AskPythonServiceToBlockShutdown()) {
        LogToPipe("Service replied BLOCK. Converting shutdown to reboot force.");
        Original_ShutdownWindowsWorkerThread(Instance, (PVOID)(EWX_REBOOT | EWX_FORCE));
    } else {
        LogToPipe("Service replied ALLOW. Permitting normal shutdown.");
        Original_ShutdownWindowsWorkerThread(Instance, Context);
    }
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
                0, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                PipeLock lk;
                g_hPipe = h;
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
                PipeLock lk;
                readOk = PipeRead(buf, sizeof(buf) - 1, &bytesRead);
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

                        LogToFile("InitThread: shutdownRva=" + shutdownRvaStr);

                        uint64_t shutdownRva = std::stoull(shutdownRvaStr, nullptr, 16);

                        HMODULE hMod = GetModuleHandleA(NULL);
                        if (!hMod) {
                            LogToFile("InitThread: GetModuleHandleA returned NULL.");
                            LogToPipe("InitThread: GetModuleHandleA returned NULL.");
                            phaseOk = false;
                        }

                        if (phaseOk) {
                            void* tShutdown = (void*)((uintptr_t)hMod + shutdownRva);

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
                                    RegPage((void*)&Hooked_ShutdownWindowsWorkerThread);
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
                PipeLock lk;
                PipeRead(discard, sizeof(discard) - 1, &dr);
            }
            LogToPipe("InitThread: Reconnected. Hooks already active, discarding RVA message.");
        }

        // ── Phase 3: Heartbeat ─────────────────────────────────────────────────
        if (phaseOk) {
            LogToFile("InitThread: Entering heartbeat loop.");
            for (;;) {
                Sleep(5000);
                PipeLock lk;
                if (!PipeWrite("PING\0", 5)) {
                    LogToFile("InitThread: Heartbeat failed, pipe broken.");
                    break;
                }
            }
        }

        // ── Cleanup before reconnect ───────────────────────────────────────────
        HANDLE oldPipe;
        {
            PipeLock lk;
            oldPipe = g_hPipe;
            g_hPipe = INVALID_HANDLE_VALUE;
        }
        if (oldPipe != INVALID_HANDLE_VALUE) CloseHandle(oldPipe);
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
