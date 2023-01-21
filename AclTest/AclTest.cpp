#include <Windows.h>
#include <iostream>

DWORD GetTokenInformation(HANDLE tokenHandle, TOKEN_INFORMATION_CLASS infoClass, std::unique_ptr<byte[]>& info)
{
    DWORD error = ERROR_SUCCESS;
    DWORD infoLength = 0;
    if (GetTokenInformation(tokenHandle, infoClass, NULL, 0, &infoLength))
    {
        std::wcerr << L"GetTokenInformation succeeded unexpectedly, infoLength " << infoLength << std::endl;
        return ERROR_BAD_ARGUMENTS;
    }

    info.reset(new byte[infoLength]);

    if (!GetTokenInformation(tokenHandle, infoClass, info.get(), infoLength, &infoLength))
    {
        error = GetLastError();
        std::wcerr << L"GetTokenInformation(0x" << std::hex << tokenHandle << std::dec << L", " << infoClass << L") failed with error " << error << std::endl;
    }

    return error;
}

DWORD GetPrivilegeName(PLUID luid, std::wstring& luidName)
{
    DWORD error = ERROR_SUCCESS;
    DWORD length = 0;

    if (LookupPrivilegeNameW(nullptr, luid, nullptr, &length))
    {
        std::wcerr << L"LookupPrivilegeName succeeded unexpectedly, length " << length << std::endl;
        error = ERROR_BAD_ARGUMENTS;
        return error;
    }

    error = GetLastError();

    if (error != ERROR_INSUFFICIENT_BUFFER)
    {
        std::wcerr << L"LookupPrivilegeName failed to get the required length, error " << error << std::endl;
        return error;
    }

    luidName.resize(length + 1);

    if (!LookupPrivilegeNameW(nullptr, luid, const_cast<wchar_t*>(luidName.c_str()), &length))
    {
        error = GetLastError();
        std::wcerr << L"LookupPrivilegeName failed with error " << error << std::endl;
    }

    return error;
}

DWORD PrintLuidAndAttributes(const LUID_AND_ATTRIBUTES& la)
{
    DWORD error = ERROR_SUCCESS;
    std::wstring luidName;

    GetPrivilegeName(const_cast<PLUID>(&la.Luid), luidName);

    std::wcout << L"LUID: " << luidName << L", attributes: 0x" << std::hex << la.Attributes << std::dec << L" ";

#define OUT_ATTRIBUTE(x) \
        if (la.Attributes & (x)) \
        { \
            std::wcout << L"|" << #x; \
        }

    OUT_ATTRIBUTE(SE_PRIVILEGE_USED_FOR_ACCESS);
    OUT_ATTRIBUTE(SE_PRIVILEGE_REMOVED);
    OUT_ATTRIBUTE(SE_PRIVILEGE_ENABLED);
    OUT_ATTRIBUTE(SE_PRIVILEGE_ENABLED_BY_DEFAULT);

#undef OUT_ATTRIBUTE

    std::wcout << std::endl;

    return error;
}

DWORD PrintTokenPrivileges(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> buffer;
    PTOKEN_PRIVILEGES privileges;

    error = GetTokenInformation(tokenHandle, TokenPrivileges, buffer);

    if (error == ERROR_SUCCESS)
    {
        privileges = (PTOKEN_PRIVILEGES)buffer.get();

        for (DWORD i = 0; i < privileges->PrivilegeCount; i++)
        {
            std::wcout << L"TokenPrivileges[" << i << L"]:" << std::endl;
            PrintLuidAndAttributes(privileges->Privileges[i]);
        }
    }
    else
    {
        std::wcerr << L"Failed to get TokenPrivileges info, error " << error << std::endl;
    }

    return error;
}

DWORD SetPrivilege(HANDLE tokenHandle, const std::wstring& privilege, bool enable)
{
    DWORD error = ERROR_SUCCESS;
    LUID luid;
    TOKEN_PRIVILEGES privileges;
    TOKEN_PRIVILEGES prevState;
    DWORD prevStateSize;

    if (!LookupPrivilegeValueW(nullptr, privilege.c_str(), &luid))
    {
        error = GetLastError();
        std::wcerr << L"Failed to look up privilege " << privilege << ", error=" << error << std::endl;
        return error;
    }

    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = (enable ? SE_PRIVILEGE_ENABLED : 0);

    prevStateSize = sizeof(prevState);

    if (!AdjustTokenPrivileges(
        tokenHandle,
        FALSE,
        &privileges,
        prevStateSize,
        &prevState,
        &prevStateSize))
    {
        error = GetLastError();
        std::wcerr << L"Failed to set token privilege " << privilege << " to " << enable << std::endl;
        return error;
    }

    std::wcout << L"Set token privilege " << privilege << " to " << enable << std::endl;

    return error;
}

class Impersonator
{
private:
    volatile bool _impersonating;

public:
    Impersonator()
        : _impersonating(false)
    {}

    ~Impersonator()
    {
        EndImpersonateSelf();
    }

    DWORD BeginImpersonateSelf()
    {
        DWORD error = ERROR_SUCCESS;
        BOOL success;

        if (_impersonating)
        {
            std::wcout << L"Already impersonating." << std::endl;
        }
        else
        {
            success = ImpersonateSelf(SecurityImpersonation);

            if (success)
            {
                std::wcout << L"Impersonating." << std::endl;
                _impersonating = true;
            }
            else
            {
                error = GetLastError();
                std::wcerr << L"Failed to impersonate, error=" << error << std::endl;
            }
        }

        return error;
    }

    DWORD EndImpersonateSelf()
    {
        DWORD error = ERROR_SUCCESS;
        BOOL success;

        if (_impersonating)
        {
            success = RevertToSelf();

            if (success)
            {
                _impersonating = false;
                std::wcout << L"Stoped impersonating." << std::endl;
            }
            else
            {
                error = GetLastError();
                std::wcerr << L"Failed to stop impersonating, error=" << error << std::endl;
            }
        }
        else
        {
            std::wcout << L"Already stoped impersonating." << std::endl;
        }

        return error;
    }
};

class ThreadToken
{
private:
    HANDLE _tokenHandle;

public:
    ThreadToken()
        : _tokenHandle(INVALID_HANDLE_VALUE)
    {}

    ~ThreadToken()
    {
        Close();
    }

    HANDLE Handle() { return _tokenHandle; }

    DWORD Open()
    {
        DWORD error = ERROR_SUCCESS;
        BOOL success;

        if (_tokenHandle == INVALID_HANDLE_VALUE)
        {
            success = OpenThreadToken(
                GetCurrentThread(),
                TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY|TOKEN_IMPERSONATE,
                TRUE,
                &_tokenHandle);

            if (success)
            {
                std::wcout << L"Opened thread token 0x" << std::hex << _tokenHandle << std::dec << std::endl;
            }
            else
            {
                error = GetLastError();
                std::wcerr << L"Failed to open thread token." << std::endl;
            }
        }
        else
        {
            std::wcout << L"Already opened thread token 0x" << std::hex << _tokenHandle << std::dec << std::endl;
        }

        return error;
    }

    DWORD Close()
    {
        DWORD error = ERROR_SUCCESS;
        BOOL success;

        if (_tokenHandle != INVALID_HANDLE_VALUE)
        {
            success = CloseHandle(_tokenHandle);

            if (success)
            {
                std::wcout << L"Closed thread token 0x" << std::hex << _tokenHandle << std::dec << std::endl;
                _tokenHandle = INVALID_HANDLE_VALUE;
            }
            else
            {
                error = GetLastError();
                std::wcerr << L"Failed to close token handle 0x" << std::hex << _tokenHandle << std::dec << std::endl;
            }
        }
        else
        {
            std::wcout << L"Already closed thread token." << std::endl;
        }

        return error;
    }
};

int wmain(int argc, wchar_t* argv[])
{
    std::cout << "Hello World!\n";

    {
        ThreadToken token;
        token.Open();
    }

    Impersonator impersonator;
    impersonator.BeginImpersonateSelf();

    {
        ThreadToken token;
        if (token.Open() == ERROR_SUCCESS)
        {
            PrintTokenPrivileges(token.Handle());

            SetPrivilege(token.Handle(), SE_BACKUP_NAME, true);

            PrintTokenPrivileges(token.Handle());
        }
    }
}