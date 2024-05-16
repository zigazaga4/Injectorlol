#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD GetProcessID(const wchar_t* processName) {
    PROCESSENTRY32W processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

bool InjectDLL(DWORD processID, const char* dllPath) {
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!processHandle) {
        return false;
    }

    LPVOID allocMemory = VirtualAllocEx(processHandle, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!allocMemory) {
        CloseHandle(processHandle);
        return false;
    }

    if (!WriteProcessMemory(processHandle, allocMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        VirtualFreeEx(processHandle, allocMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }

    HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocMemory, 0, NULL);
    if (!remoteThread) {
        VirtualFreeEx(processHandle, allocMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }

    WaitForSingleObject(remoteThread, INFINITE);

    VirtualFreeEx(processHandle, allocMemory, 0, MEM_RELEASE);
    CloseHandle(remoteThread);
    CloseHandle(processHandle);

    return true;
}

int main() {
    const wchar_t* targetProcess = L"Screenshotter.exe"; // Change this to your target process name
    const char* dllPath = "C:\\Users\\Leo\\source\\repos\\Loloverlay\\x64\\Release\\Loloverlay.dll"; // Change this to your DLL path

    DWORD processID = GetProcessID(targetProcess);
    if (!processID) {
        std::cerr << "Target process not found." << std::endl;
        return 1;
    }

    if (InjectDLL(processID, dllPath)) {
        std::cout << "DLL injected successfully." << std::endl;
    }
    else {
        std::cerr << "DLL injection failed." << std::endl;
    }

    return 0;
}