#include "hasher.h"
#include "syscall.h"

static inline BOOL GetTextSectionInfo(HMODULE hMod, DWORD* rva, DWORD* size)
{
    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt;
    IMAGE_SECTION_HEADER* sec;
    WORD                  i;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            *rva = sec->VirtualAddress;
            *size = sec->Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

static inline void EnablePrivilege(LPCWSTR pszPrivilegeName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp = { 0 };
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return;
    }

    if (!LookupPrivilegeValueW(NULL, pszPrivilegeName, &luid)) {
        DbgNtClose(hToken);
        return;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        DbgNtClose(hToken);
        return;
    }

    DbgNtClose(hToken);
    return;
}

static inline uint32_t Crc32_Section(const HMODULE hMod, const DWORD sectionRVA, const DWORD sectionSize, const HANDLE hProcess)
#if (__clang__ || __GNUC__)
    __attribute__((__target__("crc32")))
#endif
{
    MODULEINFO mi;
    if (!GetModuleInformation(hProcess, hMod, &mi, sizeof(mi))) return 0;

    BYTE* base = (BYTE*)hMod;
    BYTE* sectionBase = base + sectionRVA;
    BYTE* sectionEnd = sectionBase + sectionSize;

    if ((BYTE*)sectionBase < (BYTE*)mi.lpBaseOfDll || sectionEnd >((BYTE*)mi.lpBaseOfDll + mi.SizeOfImage))
        return 0;

    uint64_t crc = 0;
    BYTE* p = sectionBase;
    SIZE_T bytesLeft = sectionSize;

    while (bytesLeft >= 8) {
        uint64_t chunk = *(uint64_t*)p;
        crc = _mm_crc32_u64(crc, chunk);
        p += 8; bytesLeft -= 8;
    }
    while (bytesLeft > 0) {
        uint8_t b = *p;
        crc = _mm_crc32_u8((uint32_t)crc, b);
        p++; bytesLeft--;
    }

    return (uint32_t)crc;
}

void StartMemoryTracker(const HANDLE hProcess)
{
    HMODULE       mods[1024];
    DWORD         cbNeeded, mCount;
    ModuleCRC*    modCrcs;
    DWORD         i;

    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &cbNeeded)) {
        return;
    }
    mCount = cbNeeded / sizeof(HMODULE);

    modCrcs = (ModuleCRC*)calloc(mCount, sizeof(ModuleCRC));
    if (!modCrcs) {
        return;
    }

    for (i = 0; i < mCount; i++) {
        DWORD rva, size;
        if (GetTextSectionInfo(mods[i], &rva, &size)) {
            modCrcs[i].hMod = mods[i];
            modCrcs[i].textRVA = rva;
            modCrcs[i].textSize = size;

            modCrcs[i].originalCrc = Crc32_Section(mods[i], rva, size, hProcess);

        #ifdef _DEBUG
            printf("[*] Module[%u]=%p  CRC=0x%08X\n", i, mods[i], modCrcs[i].originalCrc);
        #endif
        }
    }

    EnablePrivilege(L"SeSystemtimePrivilege");

    // same as doing const HANDLE hTimeSlipEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    HANDLE hTimeSlipEvent = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0 };

    InitializeObjectAttributes(
        &objAttr,
        NULL, 
        0,    
        NULL, 
        NULL  
    );

    NTSTATUS status = DbgNtCreateEvent(
        &hTimeSlipEvent,           
        EVENT_ALL_ACCESS,            
        &objAttr,                   
        SynchronizationEvent,        
        FALSE                     
    );

    status = DbgNtSetSystemInformation((SYSTEM_INFORMATION_CLASS)SystemTimeSlipInformation, &hTimeSlipEvent, sizeof(hTimeSlipEvent));
    if (status != 0) { // we dont care if enableprivilege or createevent previously fails, we check everything here
        DbgNtClose(hTimeSlipEvent);
    }

    for (;;) {
        const DWORD minDelayMs = 500;
        const DWORD maxDelayMs = 2000;
        const DWORD randomDelayMs = minDelayMs + (rand() % (maxDelayMs - minDelayMs + 1));

        LARGE_INTEGER delay = { 0 };
        const __int64 randomDelayMs64 = (__int64)randomDelayMs;
        const __int64 conversionFactor = 10000;
        const __int64 result = -(randomDelayMs64 * conversionFactor);

        delay.QuadPart = result;

        DbgNtDelayExecution(FALSE, &delay);

        for (i = 0; i < mCount; i++) {
            if (modCrcs[i].hMod == NULL)
                continue;

            const uint32_t crc = Crc32_Section(modCrcs[i].hMod, modCrcs[i].textRVA, modCrcs[i].textSize, hProcess);

            if (crc != 0 && crc != modCrcs[i].originalCrc) {
            #ifdef _DEBUG
                wchar_t name[MAX_PATH];
                if (GetModuleFileNameW(modCrcs[i].hMod, name, _countof(name)))
                    fwprintf(stderr, L"[!] Module tampered: %s\n", name);
                else
                    fprintf(stderr, "[!] Module at %p tampered\n", modCrcs[i].hMod);

                fprintf(stderr, "    original CRC=0x%08X  new CRC=0x%08X\n",
                    modCrcs[i].originalCrc, crc);
            #endif
                free(modCrcs);
                __fastfail(ERROR_STACK_BUFFER_OVERRUN);
            }
        }

        LARGE_INTEGER timeout = { 0 };
        timeout.QuadPart = -20 * 10000;
        status = DbgNtWaitForSingleObject(
            hTimeSlipEvent, 
            FALSE,          
            &timeout        
        );

        // same as STATUS_SUCCESS, WAIT_OBJECT_0 on WaitForSingleObject
        if (status == STATUS_WAIT_0) { // ((((DWORD)0x00000000L)) + 0)
            DbgNtClose(hTimeSlipEvent);
            __fastfail(STATUS_ACCESS_VIOLATION);
        }
    }
}
