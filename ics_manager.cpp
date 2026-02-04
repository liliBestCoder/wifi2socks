#include "ics_manager.h"
#include <windows.h>
#include <thread>
#include <string>
#include <iostream>
#include <vector>

static void RunPowerShellSTA(const std::wstring& scriptPath,
    const std::wstring& publicAdapter,
    const std::wstring& privateDesc,
    int& exitCode)
{
    // STA 线程必须先 CoInitializeEx
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        exitCode = -1;
        return;
    }

    std::wstring cmdLine = L"powershell.exe -ExecutionPolicy Bypass -File \"" +
        scriptPath + L"\" -Public \"" + publicAdapter + L"\" -PrivateDesc \"" + privateDesc + L"\"";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessW(
        nullptr,
        cmdLine.data(), // 注意这里必须可写的 wchar_t*
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,  // 不显示窗口
        nullptr,
        nullptr,
        &si,
        &pi
    );

    if (!ok) {
        exitCode = -1;
        CoUninitialize();
        return;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    exitCode = (int)code;

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    CoUninitialize();
}

bool IcsManager::EnableICS(const std::wstring& publicAdapterName, const std::wstring& privateAdapterDesc)
{
    // PS 脚本路径
    std::wstring psPath = L"EnableICS.ps1";

    int exitCode = 0;

    std::thread staThread([&]() {
        RunPowerShellSTA(psPath, publicAdapterName, privateAdapterDesc, exitCode);
    });

    staThread.join();

    if (exitCode == 0) {
        return true;
    }
    else {
        return false;
    }
}

bool IcsManager::DisableICS(const std::wstring& publicAdapterName, const std::wstring& privateAdapterDesc)
{
    // PS 脚本路径
    std::wstring psPath = L"DisableICS.ps1";

    int exitCode = 0;

    std::thread staThread([&]() {
        RunPowerShellSTA(psPath, publicAdapterName, privateAdapterDesc, exitCode);
        });

    staThread.join();

    if (exitCode == 0) {
        return true;
    }
    else {
        return false;
    }
}

