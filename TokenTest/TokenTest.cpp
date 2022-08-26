#include <Windows.h>
#include <sddl.h>
#include <iostream>
#include <string>

DWORD GetTokenInformation(HANDLE tokenHandle, TOKEN_INFORMATION_CLASS infoClass, std::unique_ptr<byte[]>& info)
{
    DWORD error = ERROR_SUCCESS;
    DWORD infoLength = 0;
    if (GetTokenInformation(tokenHandle, infoClass, NULL, 0, &infoLength))
    {
        std::wcout << L"GetTokenInformation succeeded unexpectedly, infoLength " << infoLength << std::endl;
        return ERROR_BAD_ARGUMENTS;
    }

    info.reset(new byte[infoLength]);

    if (!GetTokenInformation(tokenHandle, infoClass, info.get(), infoLength, &infoLength))
    {
        error = GetLastError();
        std::wcout << L"GetTokenInformation(" << tokenHandle << L", " << infoClass << L") failed with error " << error << std::endl;
    }

    return error;
}

DWORD PrintSidAndAttributes(const SID_AND_ATTRIBUTES& sa)
{
    DWORD error = ERROR_SUCCESS;
    LPWSTR sid = nullptr;

    if (ConvertSidToStringSidW(sa.Sid, &sid))
    {
        std::wcout << L"Sid: " << std::wstring(sid) << L", attributes: 0x" << std::hex << sa.Attributes << std::dec << L" ";

#define OUT_ATTRIBUTE(x) \
        if (sa.Attributes & (x)) \
        { \
            std::wcout << L"|" << #x; \
        }

        OUT_ATTRIBUTE(SE_GROUP_LOGON_ID);
        OUT_ATTRIBUTE(SE_GROUP_RESOURCE);
        OUT_ATTRIBUTE(SE_GROUP_INTEGRITY_ENABLED);
        OUT_ATTRIBUTE(SE_GROUP_INTEGRITY);
        OUT_ATTRIBUTE(SE_GROUP_USE_FOR_DENY_ONLY);
        OUT_ATTRIBUTE(SE_GROUP_OWNER);
        OUT_ATTRIBUTE(SE_GROUP_ENABLED);
        OUT_ATTRIBUTE(SE_GROUP_ENABLED_BY_DEFAULT);
        OUT_ATTRIBUTE(SE_GROUP_MANDATORY);

        std::wcout << std::endl;

        if (LocalFree(sid) != NULL)
        {
            error = GetLastError();
            std::wcout << L"LocalFree failed with error " << error << std::endl;
        }
    }
    else
    {
        error = GetLastError();
        std::wcout << L"Sid: failed to convert, error " << error << std::endl;
    }

    return error;
}

DWORD PrintTokenUser(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> buffer;
    PTOKEN_USER user;

    error = GetTokenInformation(tokenHandle, TokenUser, buffer);

    if (error == ERROR_SUCCESS)
    {
        user = (PTOKEN_USER)buffer.get();
        std::wcout << L"TokenUser:"<< std::endl;
        PrintSidAndAttributes(user->User);
    }
    else
    {
        std::wcout << L"Failed to get TokenUser info, error " << error << std::endl;
    }

    return error;
}

DWORD PrintTokenGroups(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> buffer;
    PTOKEN_GROUPS groups;

    error = GetTokenInformation(tokenHandle, TokenGroups, buffer);

    if (error == ERROR_SUCCESS)
    {
        groups = (PTOKEN_GROUPS)buffer.get();

        for (DWORD i = 0; i < groups->GroupCount; i++)
        {
            std::wcout << L"TokenGroups[:" << i << L"]:" << std::endl;
            PrintSidAndAttributes(groups->Groups[i]);
        }
    }
    else
    {
        std::wcout << L"Failed to get TokenGroups info, error " << error << std::endl;
    }

    return error;
}


int wmain(int argc, wchar_t* argv[])
{
    DWORD error = ERROR_SUCCESS;
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
        std::wcout << L"OpenProcessToken(" << processHandle << L") succeeded with token handle " << tokenHandle << std::endl;

        PrintTokenUser(tokenHandle);
        PrintTokenGroups(tokenHandle);

        if (!CloseHandle(tokenHandle))
        {
            std::wcout << L"CloseHandle(TokenHandle:" << tokenHandle << L") failed with error " << GetLastError() << std::endl;
        }
    }

    if (processHandle != GetCurrentProcess())
    {
        if (!CloseHandle(processHandle))
        {
            std::wcout << L"CloseHandle(ProcessHandle:" << processHandle << L") failed with error " << GetLastError() << std::endl;
        }
    }

    return error;
}