// Original implementation; reference sources are research only. See README.md.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <cstdint>
#include <cstring>

static_assert(sizeof(void*) == 4, "Build for x86");
static HMODULE self;
static volatile LONG started;
static uintptr_t resumeOriginal, resumePreserved;
static uintptr_t resumeDesktopOriginal, resumeDesktopSwitch;
static uintptr_t resumeControllerOriginal, resumeControllerPreserved;
static uintptr_t resumeRouteOriginal, resumeRouteSkipped;
static uintptr_t resumeAxisReset, resumeAxisResetSkipped;
static uintptr_t resumePromptNext, resumePromptFound;
static uintptr_t resumePromptModeOriginal, resumePromptModeController;
static uintptr_t resumeRawMouseRelative, resumeRawMouseDone;
static uintptr_t resumeControllerUpdateTail;
static volatile LONG preservedVisits, preservedControllerVisits;
static volatile LONG preservedRouteVisits, preservedAxisResetVisits, disconnectRecoveries;
static volatile LONG preferredControllerPromptVisits, preferredDesktopPromptVisits, forcedControllerPromptModeVisits;
static volatile LONG rawMouseMotionVisits, desktopPromptSelections, controllerPromptSelections;
static volatile LONG mouseMotionPending;
// This distribution variant deliberately keeps prompt presentation on desktop.
// Gameplay input remains mixed; only the prompt preference differs.
static volatile LONG lastPromptDevice=0; // 0 = desktop; never changed to controller
static float previousControllerAxes[6];
static bool controllerSnapshotValid;
// Distribution builds are intentionally silent: no INI reads and no log file.
static void Log(const char*, ...) {}

// Controller +0x18 is a held-button mask. Normalized sticks are +0x268..+0x274
// and triggers are +0x278/+0x27C. Keep an analogue anchor so ordinary drift does
// not continually override newer mouse or keyboard input.
static void __cdecl ObserveControllerInput(const BYTE* controller) {
    if (!controller[0x289]) {
        controllerSnapshotValid=false;
        memset(previousControllerAxes,0,sizeof(previousControllerAxes));
        return;
    }
    DWORD pressed=0;
    memcpy(&pressed,controller+0x18,sizeof(pressed));
    bool meaningful=pressed!=0;
    for (unsigned i=0;i<6;++i) {
        float value=0.0f;
        memcpy(&value,controller+0x268+i*sizeof(float),sizeof(value));
        const float magnitude=value<0.0f ? -value : value;
        const float delta=value-previousControllerAxes[i];
        const float change=delta<0.0f ? -delta : delta;
        const float threshold=i<4 ? 0.20f : 0.10f;
        if (magnitude<=threshold) {
            previousControllerAxes[i]=value;
        } else if (!controllerSnapshotValid || change>=0.08f) {
            previousControllerAxes[i]=value;
            meaningful=true;
        }
    }
    controllerSnapshotValid=true;
    if (meaningful)
        InterlockedIncrement(&controllerPromptSelections);
}

// At this site EBP is the current device. The displaced instructions are exactly
// cmp byte [ebp+11h],0; mov byte [ebp+11h],0 (8 bytes).
// Type 1 = keyboard, type 2 = mouse, established from their constructors.
// No calls, allocation, logging, or changes to analogue values in this hook.
__declspec(naked) static void KeepDesktopDevices() {
    __asm {
        cmp dword ptr [ebp+0Ch], 1
        je preserve
        cmp dword ptr [ebp+0Ch], 2
        je preserve
        cmp byte ptr [ebp+11h], 0
        mov byte ptr [ebp+11h], 0
        jmp dword ptr [resumeOriginal]
    preserve:
        mov byte ptr [ebp+11h], 1
        lock inc dword ptr [preservedVisits]
        jmp dword ptr [resumePreserved]
    }
}

// A selected controller must bypass the retained-keyboard guard so native desktop
// selection can run. Later hooks preserve it only while it remains connected.
// With no selected controller, keep the original keyboard-selected test.
__declspec(naked) static void GuardDesktopSwitch() {
    __asm {
        mov edx, dword ptr [esi+4A7Ch]
        test edx, edx
        jz original
        cmp byte ptr [edx+289h], 0
        jne connected
        lock inc dword ptr [disconnectRecoveries]
    connected:
        jmp dword ptr [resumeDesktopSwitch]
    original:
        mov edx, dword ptr [esi+4A74h]
        cmp byte ptr [edx+11h], 0
        jmp dword ptr [resumeDesktopOriginal]
    }
}

// The mirrored desktop-selection loop clears every device. Preserve connected
// native controllers (type 0); disconnected controllers and other device types
// execute the original comparison/store and callbacks.
__declspec(naked) static void KeepConnectedControllers() {
    __asm {
        cmp dword ptr [edi+0Ch], 0
        jne original
        cmp byte ptr [edi+289h], 0
        je original
        mov byte ptr [edi+11h], 1
        lock inc dword ptr [preservedControllerVisits]
        jmp dword ptr [resumeControllerPreserved]
    original:
        cmp byte ptr [edi+11h], 0
        mov byte ptr [edi+11h], 0
        jmp dword ptr [resumeControllerOriginal]
    }
}

// Stock desktop selection disables the controller route after its deselection
// loop. Skip only that call while the selected controller is still connected.
__declspec(naked) static void PreserveConnectedControllerRoute() {
    __asm {
        mov eax, dword ptr [esi+4A7Ch]
        test eax, eax
        jz original
        cmp byte ptr [eax+289h], 0
        je original
        lock inc dword ptr [preservedRouteVisits]
        jmp dword ptr [resumeRouteSkipped]
    original:
        mov ecx, dword ptr [esi+4A80h]
        test ecx, ecx
        je skipped
        jmp dword ptr [resumeRouteOriginal]
    skipped:
        jmp dword ptr [resumeRouteSkipped]
    }
}

// Binding contexts normally clear all resolved axes when keyboard is selected.
// Keep those axes only when that context's type-0 controller is selected and
// connected; otherwise preserve the original keyboard-selected reset exactly.
__declspec(naked) static void PreserveConnectedControllerAxes() {
    __asm {
        cmp byte ptr [esi+11h], 0
        je originalSkipped
        mov eax, dword ptr [ecx+103Ch]
        test eax, eax
        jz reset
        cmp byte ptr [eax+11h], 0
        je reset
        cmp byte ptr [eax+289h], 0
        je reset
        lock inc dword ptr [preservedAxisResetVisits]
    originalSkipped:
        jmp dword ptr [resumeAxisResetSkipped]
    reset:
        jmp dword ptr [resumeAxisReset]
    }
}

// Prompt resolution returns the first selected binding. Prefer a controller
// binding only when one exists later in the action's binding list, retaining the
// desktop binding as a fallback for actions without controller support.
__declspec(naked) static void PreferControllerPromptBinding() {
    __asm {
        cmp dword ptr [edx+0Ch], 0
        je controllerCandidate
        cmp dword ptr [lastPromptDevice], 1
        jne original
        push ebx
        push ebp
        mov ebx, dword ptr [ecx+103Ch]
        test ebx, ebx
        jz fallback
        cmp byte ptr [ebx+11h], 0
        je fallback
        cmp byte ptr [ebx+289h], 0
        je fallback
        mov ebx, eax
        mov ebp, esi
    scan:
        inc ebp
        cmp ebp, edi
        jae fallback
        add ebx, 8
        cmp word ptr [ebx+4], 0FFFFh
        je scan
        cmp byte ptr [ebx+6], 0
        jne scan
        pop ebp
        pop ebx
        lock inc dword ptr [preferredControllerPromptVisits]
        jmp dword ptr [resumePromptNext]
    fallback:
        pop ebp
        pop ebx
        jmp original
    controllerCandidate:
        cmp dword ptr [lastPromptDevice], 0
        jne original
        push ebx
        push ebp
        push edx
        mov ebx, eax
        mov ebp, esi
    scanDesktop:
        inc ebp
        cmp ebp, edi
        jae desktopFallback
        add ebx, 8
        cmp word ptr [ebx+4], 0FFFFh
        je scanDesktop
        movzx edx, byte ptr [ebx+6]
        test edx, edx
        je scanDesktop
        cmp edx, 2
        ja scanDesktop
        mov edx, dword ptr [ecx+edx*4+103Ch]
        test edx, edx
        jz scanDesktop
        cmp byte ptr [edx+11h], 0
        je scanDesktop
        pop edx
        pop ebp
        pop ebx
        lock inc dword ptr [preferredDesktopPromptVisits]
        jmp dword ptr [resumePromptNext]
    desktopFallback:
        pop edx
        pop ebp
        pop ebx
    original:
        cmp byte ptr [edx+11h], 0
        je next
        jmp dword ptr [resumePromptFound]
    next:
        jmp dword ptr [resumePromptNext]
    }
}

// The central prompt formatter otherwise changes to keyboard mode whenever the
// keyboard is selected. Keep controller formatting while the context's type-0
// controller remains selected and connected; preserve the original test otherwise.
__declspec(naked) static void ForceControllerPromptMode() {
    __asm {
        push edx
        cmp dword ptr [lastPromptDevice], 1
        jne original
        mov edx, dword ptr [edi+103Ch]
        test edx, edx
        jz original
        cmp byte ptr [edx+11h], 0
        je original
        cmp byte ptr [edx+289h], 0
        je original
        pop edx
        mov byte ptr [esp+0BFh], 0
        lock inc dword ptr [forcedControllerPromptModeVisits]
        jmp dword ptr [resumePromptModeController]
    original:
        pop edx
        cmp byte ptr [eax+11h], 0
        mov byte ptr [esp+0BFh], 1
        jmp dword ptr [resumePromptModeOriginal]
    }
}

// Raw relative movement is accumulated regardless of selection, but stock mouse
// activity reports only buttons. Record nonzero relative packets for one native
// arbitration query and make them the latest desktop presentation input.
__declspec(naked) static void RecordRawMouseMotion() {
    __asm {
        test byte ptr [edi+10h], 1
        jne done
        cmp dword ptr [edi+1Ch], 0
        jne moved
        cmp dword ptr [edi+20h], 0
        je relative
    moved:
        mov dword ptr [mouseMotionPending], 1
        lock inc dword ptr [rawMouseMotionVisits]
        cmp dword ptr [lastPromptDevice], 0
        je relative
        mov dword ptr [lastPromptDevice], 0
        lock inc dword ptr [desktopPromptSelections]
    relative:
        jmp dword ptr [resumeRawMouseRelative]
    done:
        jmp dword ptr [resumeRawMouseDone]
    }
}

// Preserve the original button result and supplement it with one pending raw
// movement report.
__declspec(naked) static void ReportMouseActivity() {
    __asm {
        xor eax, eax
        mov edx, dword ptr [ecx+54h]
        cmp edx, eax
        je motion
        mov dword ptr [mouseMotionPending], 0
        cmp dword ptr [lastPromptDevice], 0
        je active
        mov dword ptr [lastPromptDevice], 0
        lock inc dword ptr [desktopPromptSelections]
    active:
        mov eax, 1
        ret
    motion:
        xchg eax, dword ptr [mouseMotionPending]
        ret
    }
}

// Keyboard +0x224 is the stock one-frame activity byte used by arbitration.
__declspec(naked) static void ReportKeyboardActivity() {
    __asm {
        cmp byte ptr [ecx+224h], 0
        je done
        cmp dword ptr [lastPromptDevice], 0
        je done
        mov dword ptr [lastPromptDevice], 0
        lock inc dword ptr [desktopPromptSelections]
    done:
        mov al, byte ptr [ecx+224h]
        ret
    }
}

// Run after the native XInput update has stored its final trigger value. The
// original epilogue continues at pop esi; no input state is rewritten.
__declspec(naked) static void ObserveControllerUpdate() {
    __asm {
        pop edi
        movss dword ptr [esi+27Ch], xmm1
        pushfd
        pushad
        push esi
        call ObserveControllerInput
        add esp, 4
        popad
        popfd
        jmp dword ptr [resumeControllerUpdateTail]
    }
}

static bool VerifiedFile(const wchar_t* path) {
    // Exact supported executable, including code outside the target pattern.
    constexpr BYTE expected[32] = {
        0xdd,0xe6,0x65,0x21,0x79,0x8a,0xae,0x8c,0x39,0xed,0x4e,0x7a,0x34,0x00,0xf5,0x61,
        0xfc,0xec,0xff,0xf8,0x36,0x19,0xd1,0x42,0x6b,0x9e,0x0c,0xed,0xf5,0x81,0x9a,0x90};
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    HCRYPTPROV prov = 0; HCRYPTHASH hash = 0;
    bool ok = CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) != FALSE;
    if (ok) ok = CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash) != FALSE;
    BYTE buffer[65536]; DWORD read;
    while (ok) {
        if (!ReadFile(f, buffer, sizeof(buffer), &read, nullptr)) { ok=false; break; }
        if (!read) break;
        ok = CryptHashData(hash, buffer, read, 0) != FALSE;
    }
    BYTE digest[32] = {}; DWORD len=sizeof(digest);
    if (ok) ok = CryptGetHashParam(hash, HP_HASHVAL, digest, &len, 0) && len==32 && !memcmp(digest,expected,32);
    if (hash) CryptDestroyHash(hash);
    if (prov) CryptReleaseContext(prov,0);
    CloseHandle(f); return ok;
}

struct Patch {
    BYTE* target;
    const BYTE* expected;
    const BYTE* replacement;
    size_t size;
};

// Freeze peers only for the short code writes. Validate and make each target
// writable before changing any target, so the multi-hook install is all-or-none.
static bool Install(Patch* patches, size_t patchCount) {
    if (patchCount>32) return false;
    HANDLE threads[512] = {}; DWORD count=0;
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if (snap==INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 ent={sizeof(ent)}; bool ok=true;
    if (!Thread32First(snap,&ent)) ok=false;
    else do {
        if (ent.th32OwnerProcessID!=GetCurrentProcessId() || ent.th32ThreadID==GetCurrentThreadId()) continue;
        if (count==512) { ok=false; break; }
        HANDLE t=OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,ent.th32ThreadID);
        if (!t) { ok=false; break; }
        threads[count++]=t;
    } while (Thread32Next(snap,&ent));
    CloseHandle(snap);
    DWORD suspended=0;
    if (ok) for (; suspended<count; ++suspended) {
        if (SuspendThread(threads[suspended])==DWORD(-1)) { ok=false; break; }
    }
    if (ok) for (DWORD i=0;i<count;++i) {
        CONTEXT c={}; c.ContextFlags=CONTEXT_CONTROL;
        if (!GetThreadContext(threads[i],&c)) { ok=false; break; }
        for (size_t p=0;p<patchCount;++p) {
            const uintptr_t start=reinterpret_cast<uintptr_t>(patches[p].target);
            if (c.Eip>=start && c.Eip<start+patches[p].size) { ok=false; break; }
        }
        if (!ok) break;
    }
    if (ok) for (size_t p=0;p<patchCount;++p)
        if (memcmp(patches[p].target,patches[p].expected,patches[p].size)) { ok=false; break; }
    DWORD oldProtection[32]={};
    size_t writableCount=0;
    if (ok) for (;writableCount<patchCount;++writableCount) {
        if (!VirtualProtect(patches[writableCount].target,patches[writableCount].size,
                            PAGE_EXECUTE_READWRITE,&oldProtection[writableCount])) { ok=false; break; }
    }
    bool protectionRestored=true;
    if (ok) {
        for (size_t p=0;p<patchCount;++p)
            memcpy(patches[p].target,patches[p].replacement,patches[p].size);
        for (size_t p=0;p<patchCount;++p)
            FlushInstructionCache(GetCurrentProcess(),patches[p].target,patches[p].size);
    }
    // Reverse order is required when multiple targets share the same page.
    for (size_t p=writableCount;p>0;--p) {
        DWORD unused;
        if (!VirtualProtect(patches[p-1].target,patches[p-1].size,oldProtection[p-1],&unused))
            protectionRestored=false;
    }
    for (DWORD i=0;i<suspended;++i) ResumeThread(threads[i]);
    for (DWORD i=0;i<count;++i) CloseHandle(threads[i]);
    if (!protectionRestored) Log("WARNING: restoring hook page protection failed");
    return ok;
}

static DWORD WINAPI Initialize(void*) {
    Log("MixedInput 0.7 KBM Prompts - desktop prompt binding; raw-mouse activation; gameplay verification in progress");
    {
        wchar_t exe[MAX_PATH]; GetModuleFileNameW(nullptr,exe,MAX_PATH);
        const wchar_t* name=wcsrchr(exe,L'\\');
        if (!name || _wcsicmp(name+1,L"AI.exe") || !VerifiedFile(exe)) {
            Log("Unsupported executable name/SHA-256 (or read/hash failure); no changes"); goto done;
        }
        BYTE* base=reinterpret_cast<BYTE*>(GetModuleHandleW(nullptr));
        auto dos=reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        auto nt=reinterpret_cast<IMAGE_NT_HEADERS32*>(base+dos->e_lfanew);
        if (dos->e_magic!=IMAGE_DOS_SIGNATURE || nt->Signature!=IMAGE_NT_SIGNATURE ||
            nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_I386 || nt->FileHeader.TimeDateStamp!=1424169373 ||
            nt->OptionalHeader.SizeOfImage!=0x1f81000) { Log("PE identity mismatch; no changes"); goto done; }
        // Entire loop context contains no relocations; validate a unique match in
        // the executable section and its independently established expected RVA.
        const BYTE context[]={0x8b,0x4e,0x40,0x8b,0x2c,0x99,0x80,0x7d,0x11,0x00,
            0xc6,0x45,0x11,0x00,0x0f,0x95,0xc0,0x84,0xc0,0x74,0x1a,0x8b,0x55,0x00,
            0x8b,0x42,0x40,0x8b,0xcd,0xff,0xd0,0x80,0x7d,0x11,0x00,0x75,0x0a,
            0x8b,0x55,0x00,0x8b,0x42,0x28,0x8b,0xcd,0xff,0xd0,0x43,0x3b,0x5c,0x24,0x14,0x72,0xca};
        const BYTE desktopContext[]={0x80,0x7c,0x24,0x13,0x00,0x0f,0x85,0xdf,0x00,0x00,0x00,
            0x8b,0x96,0x74,0x4a,0x00,0x00,0x80,0x7a,0x11,0x00,0x0f,0x85,0xcf,0x00,0x00,0x00,
            0x8b,0x86,0x70,0x4a,0x00,0x00,0x80,0xb8,0xae,0x00,0x00,0x00,0x00};
        const BYTE controllerContext[]={0x8b,0x5c,0x24,0x14,0x33,0xed,0x85,0xdb,0x74,0x32,
            0x8b,0x4e,0x40,0x8b,0x3c,0xa9,0x80,0x7f,0x11,0x00,0xc6,0x47,0x11,0x00,
            0x0f,0x95,0xc0,0x84,0xc0,0x74,0x18,0x8b,0x17,0x8b,0x42,0x40,0x8b,0xcf,0xff,0xd0};
        const BYTE routeContext[]={0x45,0x3b,0xeb,0x72,0xce,0x8b,0x8e,0x80,0x4a,0x00,0x00,
            0x85,0xc9,0x74,0x09,0x8b,0x11,0x8b,0x42,0x10,0x6a,0x04,0xff,0xd0,
            0x8b,0xbe,0x70,0x4a,0x00,0x00};
        const BYTE axisContext[]={0x0f,0x57,0xed,0x56,0x8b,0xb1,0x40,0x10,0x00,0x00,
            0x85,0xf6,0x74,0x32,0x80,0x7e,0x10,0x00,0x74,0x2c,0x80,0x7e,0x11,0x00,
            0x74,0x26,0x33,0xc0,0x39,0x81,0x58,0x10,0x00,0x00,0x76,0x1c,0x8d,0x91,
            0x80,0x0a,0x00,0x00};
        const BYTE promptContext[]={0x56,0x33,0xf6,0x85,0xff,0x74,0x29,0x8b,0x42,0x30,
            0x8b,0xff,0xba,0xff,0xff,0x00,0x00,0x66,0x39,0x50,0x04,0x74,0x11,0x0f,
            0xb6,0x50,0x06,0x8b,0x94,0x91,0x3c,0x10,0x00,0x00,0x80,0x7a,0x11,0x00,
            0x75,0x23,0x46,0x83,0xc0,0x08,0x3b,0xf7,0x72,0xdc};
        const BYTE promptModeContext[]={0x85,0xc0,0x74,0x14,0x80,0x78,0x10,0x00,0x74,0x0e,
            0x80,0x78,0x11,0x00,0xc6,0x84,0x24,0xbf,0x00,0x00,0x00,0x01,0x75,0x08,
            0xc6,0x84,0x24,0xbf,0x00,0x00,0x00,0x00};
        const BYTE rawMouseContext[]={0xf6,0x47,0x10,0x01,0x75,0x0c,0x8b,0x47,0x1c,0x01,0x41,0x64,
            0x8b,0x57,0x20,0x01,0x51,0x68,0x5f,0x5b,0xc2,0x04,0x00};
        const BYTE mouseActivityContext[]={0x33,0xc0,0x39,0x41,0x54,0x0f,0x95,0xc0,0xc3};
        const BYTE keyboardActivityContext[]={0x8a,0x81,0x24,0x02,0x00,0x00,0xc3};
        const BYTE controllerUpdateContext[]={0x5f,0xf3,0x0f,0x11,0x8e,0x7c,0x02,0x00,0x00,0x5e,0x8b,0xe5,0x5d,0xc3};
        BYTE* found=nullptr; BYTE* foundDesktop=nullptr; BYTE* foundController=nullptr; BYTE* foundRoute=nullptr; BYTE* foundAxis=nullptr; BYTE* foundPrompt=nullptr; BYTE* foundPromptMode=nullptr;
        BYTE* foundRawMouse=nullptr; BYTE* foundMouseActivity=nullptr; BYTE* foundKeyboardActivity=nullptr; BYTE* foundControllerUpdate=nullptr;
        unsigned matches=0, desktopMatches=0, controllerMatches=0, routeMatches=0, axisMatches=0, promptMatches=0, promptModeMatches=0;
        unsigned rawMouseMatches=0, mouseActivityMatches=0, keyboardActivityMatches=0, controllerUpdateMatches=0;
        auto section=IMAGE_FIRST_SECTION(nt);
        for (unsigned s=0;s<nt->FileHeader.NumberOfSections;++s) {
            if (!(section[s].Characteristics&IMAGE_SCN_MEM_EXECUTE)) continue;
            const size_t size=section[s].Misc.VirtualSize;
            if (size<sizeof(context) || section[s].VirtualAddress+size>nt->OptionalHeader.SizeOfImage) continue;
            BYTE* text=base+section[s].VirtualAddress;
            for (size_t i=0;i<=size-sizeof(context);++i)
                if (!memcmp(text+i,context,sizeof(context))) { found=text+i; ++matches; }
            for (size_t i=0;i<=size-sizeof(desktopContext);++i)
                if (!memcmp(text+i,desktopContext,sizeof(desktopContext))) { foundDesktop=text+i; ++desktopMatches; }
            for (size_t i=0;i<=size-sizeof(controllerContext);++i)
                if (!memcmp(text+i,controllerContext,sizeof(controllerContext))) { foundController=text+i; ++controllerMatches; }
            for (size_t i=0;i<=size-sizeof(routeContext);++i)
                if (!memcmp(text+i,routeContext,sizeof(routeContext))) { foundRoute=text+i; ++routeMatches; }
            for (size_t i=0;i<=size-sizeof(axisContext);++i)
                if (!memcmp(text+i,axisContext,sizeof(axisContext))) { foundAxis=text+i; ++axisMatches; }
            for (size_t i=0;i<=size-sizeof(promptContext);++i)
                if (!memcmp(text+i,promptContext,sizeof(promptContext))) { foundPrompt=text+i; ++promptMatches; }
            for (size_t i=0;i<=size-sizeof(promptModeContext);++i)
                if (!memcmp(text+i,promptModeContext,sizeof(promptModeContext))) { foundPromptMode=text+i; ++promptModeMatches; }
            for (size_t i=0;i<=size-sizeof(rawMouseContext);++i)
                if (!memcmp(text+i,rawMouseContext,sizeof(rawMouseContext))) { foundRawMouse=text+i; ++rawMouseMatches; }
            for (size_t i=0;i<=size-sizeof(mouseActivityContext);++i)
                if (!memcmp(text+i,mouseActivityContext,sizeof(mouseActivityContext))) { foundMouseActivity=text+i; ++mouseActivityMatches; }
            for (size_t i=0;i<=size-sizeof(keyboardActivityContext);++i)
                if (!memcmp(text+i,keyboardActivityContext,sizeof(keyboardActivityContext))) { foundKeyboardActivity=text+i; ++keyboardActivityMatches; }
            for (size_t i=0;i<=size-sizeof(controllerUpdateContext);++i)
                if (!memcmp(text+i,controllerUpdateContext,sizeof(controllerUpdateContext))) { foundControllerUpdate=text+i; ++controllerUpdateMatches; }
        }
        if (matches!=1 || found!=base+0x57cc10) { Log("Loop validation failed (matches=%u); no changes",matches); goto done; }
        if (desktopMatches!=1 || foundDesktop!=base+0x57cd4f) {
            Log("Desktop guard validation failed (matches=%u); no changes",desktopMatches); goto done;
        }
        if (controllerMatches!=1 || foundController!=base+0x57cd89) {
            Log("Controller loop validation failed (matches=%u); no changes",controllerMatches); goto done;
        }
        if (routeMatches!=1 || foundRoute!=base+0x57cdc0) {
            Log("Controller route validation failed (matches=%u); no changes",routeMatches); goto done;
        }
        if (axisMatches!=1 || foundAxis!=base+0x57d6c0) {
            Log("Axis reset validation failed (matches=%u); no changes",axisMatches); goto done;
        }
        if (promptMatches!=1 || foundPrompt!=base+0x57d454) {
            Log("Prompt binding validation failed (matches=%u); no changes",promptMatches); goto done;
        }
        if (promptModeMatches!=1 || foundPromptMode!=base+0x42d044) {
            Log("Prompt mode validation failed (matches=%u); no changes",promptModeMatches); goto done;
        }
        if (rawMouseMatches!=1 || foundRawMouse!=base+0x60e99c) {
            Log("Raw mouse validation failed (matches=%u); no changes",rawMouseMatches); goto done;
        }
        if (mouseActivityMatches!=1 || foundMouseActivity!=base+0x9bbe70) {
            Log("Mouse activity validation failed (matches=%u); no changes",mouseActivityMatches); goto done;
        }
        if (keyboardActivityMatches!=1 || foundKeyboardActivity!=base+0x60ee00) {
            Log("Keyboard activity validation failed (matches=%u); no changes",keyboardActivityMatches); goto done;
        }
        if (controllerUpdateMatches!=1 || foundControllerUpdate!=base+0x60f264) {
            Log("Controller update validation failed (matches=%u); no changes",controllerUpdateMatches); goto done;
        }
        // Independent control-flow checks: native selected-controller assignment,
        // keyboard-selected guard and tail-call into this arbitration routine.
        const BYTE selected[]={0x89,0xbe,0x7c,0x4a,0,0};
        const BYTE connectionFallback[]={0x80,0xb8,0x89,0x02,0,0,0,0x75,0x02,0xb3,0x01};
        const BYTE tail[]={0xe9,0x85,0xc1,0xfe,0xff};
        if (memcmp(base+0x57cc6d,selected,sizeof(selected)) ||
            memcmp(base+0x57cd44,connectionFallback,sizeof(connectionFallback)) ||
            memcmp(base+0x590a36,tail,sizeof(tail))) { Log("Arbitration cross-check failed; no changes"); goto done; }
        HMODULE pinned;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(&KeepDesktopDevices),&pinned)) { Log("Module pin failed; no changes"); goto done; }
        BYTE* target=found+6;
        resumeOriginal=reinterpret_cast<uintptr_t>(target+8);
        resumePreserved=reinterpret_cast<uintptr_t>(found+47);
        BYTE jump[8]={0xe9,0,0,0,0,0x90,0x90,0x90};
        const uint32_t relative=static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&KeepDesktopDevices)-reinterpret_cast<uintptr_t>(target)-5);
        memcpy(jump+1,&relative,4);
        BYTE* desktopTarget=foundDesktop+11;
        resumeDesktopOriginal=reinterpret_cast<uintptr_t>(desktopTarget+10);
        resumeDesktopSwitch=reinterpret_cast<uintptr_t>(foundDesktop+27);
        BYTE desktopJump[10]={0xe9,0,0,0,0,0x90,0x90,0x90,0x90,0x90};
        const uint32_t desktopRelative=static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&GuardDesktopSwitch)-reinterpret_cast<uintptr_t>(desktopTarget)-5);
        memcpy(desktopJump+1,&desktopRelative,4);
        BYTE* controllerTarget=foundController+16;
        resumeControllerOriginal=reinterpret_cast<uintptr_t>(controllerTarget+8);
        resumeControllerPreserved=reinterpret_cast<uintptr_t>(foundController+55);
        BYTE controllerJump[8]={0xe9,0,0,0,0,0x90,0x90,0x90};
        const uint32_t controllerRelative=static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&KeepConnectedControllers)-reinterpret_cast<uintptr_t>(controllerTarget)-5);
        memcpy(controllerJump+1,&controllerRelative,4);
        BYTE* routeTarget=foundRoute+5;
        resumeRouteOriginal=reinterpret_cast<uintptr_t>(routeTarget+10);
        resumeRouteSkipped=reinterpret_cast<uintptr_t>(foundRoute+24);
        BYTE routeJump[10]={0xe9,0,0,0,0,0x90,0x90,0x90,0x90,0x90};
        const uint32_t routeRelative=static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&PreserveConnectedControllerRoute)-reinterpret_cast<uintptr_t>(routeTarget)-5);
        memcpy(routeJump+1,&routeRelative,4);
        BYTE* axisTarget=foundAxis+20;
        resumeAxisReset=reinterpret_cast<uintptr_t>(axisTarget+6);
        resumeAxisResetSkipped=reinterpret_cast<uintptr_t>(foundAxis+64);
        BYTE axisJump[6]={0xe9,0,0,0,0,0x90};
        const uint32_t axisRelative=static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&PreserveConnectedControllerAxes)-reinterpret_cast<uintptr_t>(axisTarget)-5);
        memcpy(axisJump+1,&axisRelative,4);
        BYTE* promptTarget=foundPrompt+34;
        resumePromptNext=reinterpret_cast<uintptr_t>(promptTarget+6);
        resumePromptFound=reinterpret_cast<uintptr_t>(foundPrompt+75);
        BYTE promptJump[6]={0xe9,0,0,0,0,0x90};
        const uint32_t promptRelative=static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&PreferControllerPromptBinding)-reinterpret_cast<uintptr_t>(promptTarget)-5);
        memcpy(promptJump+1,&promptRelative,4);
        BYTE* promptModeTarget=foundPromptMode+10;
        resumePromptModeOriginal=reinterpret_cast<uintptr_t>(promptModeTarget+12);
        resumePromptModeController=reinterpret_cast<uintptr_t>(foundPromptMode+32);
        BYTE promptModeJump[12]={0xe9,0,0,0,0,0x90,0x90,0x90,0x90,0x90,0x90,0x90};
        const uint32_t promptModeRelative=static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&ForceControllerPromptMode)-reinterpret_cast<uintptr_t>(promptModeTarget)-5);
        memcpy(promptModeJump+1,&promptModeRelative,4);
        BYTE* rawMouseTarget=foundRawMouse;
        resumeRawMouseRelative=reinterpret_cast<uintptr_t>(foundRawMouse+6);
        resumeRawMouseDone=reinterpret_cast<uintptr_t>(foundRawMouse+18);
        BYTE rawMouseJump[6]={0xe9,0,0,0,0,0x90};
        const uint32_t rawMouseRelative=static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&RecordRawMouseMotion)-reinterpret_cast<uintptr_t>(rawMouseTarget)-5);
        memcpy(rawMouseJump+1,&rawMouseRelative,4);
        BYTE* mouseActivityTarget=foundMouseActivity;
        BYTE mouseActivityJump[9]={0xe9,0,0,0,0,0x90,0x90,0x90,0x90};
        const uint32_t mouseActivityRelative=static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&ReportMouseActivity)-reinterpret_cast<uintptr_t>(mouseActivityTarget)-5);
        memcpy(mouseActivityJump+1,&mouseActivityRelative,4);
        BYTE* keyboardActivityTarget=foundKeyboardActivity;
        BYTE keyboardActivityJump[7]={0xe9,0,0,0,0,0x90,0x90};
        const uint32_t keyboardActivityRelative=static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&ReportKeyboardActivity)-reinterpret_cast<uintptr_t>(keyboardActivityTarget)-5);
        memcpy(keyboardActivityJump+1,&keyboardActivityRelative,4);
        BYTE* controllerUpdateTarget=foundControllerUpdate;
        resumeControllerUpdateTail=reinterpret_cast<uintptr_t>(foundControllerUpdate+9);
        BYTE controllerUpdateJump[9]={0xe9,0,0,0,0,0x90,0x90,0x90,0x90};
        const uint32_t controllerUpdateRelative=static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&ObserveControllerUpdate)-reinterpret_cast<uintptr_t>(controllerUpdateTarget)-5);
        memcpy(controllerUpdateJump+1,&controllerUpdateRelative,4);
        Patch patches[]={
            {target,context+6,jump,sizeof(jump)},
            {desktopTarget,desktopContext+11,desktopJump,sizeof(desktopJump)},
            {controllerTarget,controllerContext+16,controllerJump,sizeof(controllerJump)},
            {routeTarget,routeContext+5,routeJump,sizeof(routeJump)},
            {axisTarget,axisContext+20,axisJump,sizeof(axisJump)},
            {promptTarget,promptContext+34,promptJump,sizeof(promptJump)},
            {promptModeTarget,promptModeContext+10,promptModeJump,sizeof(promptModeJump)},
            {rawMouseTarget,rawMouseContext,rawMouseJump,sizeof(rawMouseJump)},
            {mouseActivityTarget,mouseActivityContext,mouseActivityJump,sizeof(mouseActivityJump)},
            {keyboardActivityTarget,keyboardActivityContext,keyboardActivityJump,sizeof(keyboardActivityJump)},
            {controllerUpdateTarget,controllerUpdateContext,controllerUpdateJump,sizeof(controllerUpdateJump)}
        };
        if (!Install(patches,sizeof(patches)/sizeof(patches[0]))) { Log("Atomic hook installation failed; no changes applied"); goto done; }
        Log("SUCCESS: 11 mixed-input hooks installed, base=%p",base);
        Log("Raw mouse movement enters the native desktop transition; controller, route and analogue axes are preserved");
        Log("Prompt binding remains keyboard/mouse-style while gameplay input stays mixed");
        Log("Native XInput, analog values, bindings, camera math and rumble functions unchanged");
    }
done:
    return 0;
}

extern "C" __declspec(dllexport) void InitializeASI() {
    if (InterlockedCompareExchange(&started,1,0)) return;
    HANDLE thread=CreateThread(nullptr,0,Initialize,nullptr,0,nullptr);
    if (thread) CloseHandle(thread);
    else { InterlockedExchange(&started,0); OutputDebugStringA("MixedInput: initialization thread creation failed"); }
}

BOOL WINAPI DllMain(HMODULE module,DWORD reason,LPVOID) {
    if (reason==DLL_PROCESS_ATTACH) {
        self=module;
        DisableThreadLibraryCalls(module);
        // Older loaders need DllMain fallback. Worker cannot execute before this
        // returns; all file IO, scanning and patching run outside the loader lock.
        InitializeASI();
    }
    return TRUE;
}
