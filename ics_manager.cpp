#include "ics_manager.h"
#include <windows.h>
#include <thread>
#include <string>
#include <iostream>
#include <vector>

static void RunPowerShellSTA(const std::wstring& scriptPath,
    const std::wstring& publicAdapter,
    const std::wstring& privateDesc,
    std::wstring& output)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        return;
    }

    // 创建管道
    HANDLE hRead = nullptr;
    HANDLE hWrite = nullptr;
    SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        CoUninitialize();
        return;
    }

    // 保证子进程关闭写端后不会继承
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    std::wstring cmdLine = L"powershell.exe -ExecutionPolicy Bypass -File \"" +
        scriptPath + L"\" -Public \"" + publicAdapter + L"\" -PrivateDesc \"" + privateDesc + L"\"";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessW(nullptr, cmdLine.data(),
        nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi);

    // 子进程不再需要写句柄
    CloseHandle(hWrite);

    if (!ok) {
        CloseHandle(hRead);
        CoUninitialize();
        return;
    }

    // 读取输出
    std::vector<char> buffer(4096);
    DWORD bytesRead = 0;
    output.clear();
   
    while (ReadFile(hRead, buffer.data(), (DWORD)buffer.size(), &bytesRead, nullptr) && bytesRead > 0) {
        // 转成 wstring
        int wlen = MultiByteToWideChar(CP_UTF8, 0, buffer.data(), bytesRead, nullptr, 0);
        std::wstring wchunk(wlen, 0);
        MultiByteToWideChar(CP_UTF8, 0, buffer.data(), bytesRead, wchunk.data(), wlen);

        output += wchunk;
    }

    CloseHandle(hRead);

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    CoUninitialize();
}

bool IcsManager::EnableICS(const std::wstring& publicAdapterName, const std::wstring& privateAdapterDesc)
{
    // PS 脚本路径
    std::wstring psPath = L"EnableICS.ps1";

    std::wstring output = L"";

    std::thread staThread([&]() {
        RunPowerShellSTA(psPath, publicAdapterName, privateAdapterDesc, output);
    });

    staThread.join();

    if (output.find(L"successfully") != std::wstring::npos) {
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

    std::wstring output = L"";

    std::thread staThread([&]() {
        RunPowerShellSTA(psPath, publicAdapterName, privateAdapterDesc, output);
    });

    staThread.join();

    if (output.find(L"successfully") != std::wstring::npos) {
        return true;
    }
    else {
        return false;
    }
}

