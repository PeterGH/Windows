#include <Windows.h>
#include <iostream>
#include <string>

int wmain(int argc, wchar_t* argv[])
{
    DWORD error = S_OK;
    HANDLE tokenHandle = INVALID_HANDLE_VALUE;

    HANDLE processHandle = GetCurrentProcess();

    if (argc >= 2)
    {
        DWORD processId = std::stoul(argv[1]);
        processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE /* InheritHandle */, processId);
        if (processHandle == NULL)
        {
            error = GetLastError();
            std::wcout << L"OpenProcess(" << processId << L") failed with error " << error << std::endl;
            return error;
        }
    }

    if (!OpenProcessToken(processHandle, TOKEN_ALL_ACCESS, &tokenHandle))
    {
        error = GetLastError();
        std::wcout << L"OpenProcessToken(" << processHandle << L") failed with error " << error << std::endl;
    }
    else
    {
        std::wcout << L"OpenProcessToken succeeded" << std::endl;

        if (!CloseHandle(tokenHandle))
        {
            error = GetLastError();
            std::wcout << L"CloseHandle(TokenHandle:" << tokenHandle << L") failed with error " << error << std::endl;
        }
    }

    if (processHandle != GetCurrentProcess())
    {
        if (!CloseHandle(processHandle))
        {
            error = GetLastError();
            std::wcout << L"CloseHandle(ProcessHandle:" << processHandle << L") failed with error " << error << std::endl;
        }
    }

    return error;
}