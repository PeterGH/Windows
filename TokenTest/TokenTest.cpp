#include <Windows.h>
#include <sddl.h>
#include <map>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#define STRING(x) L#x

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

#undef OUT_ATTRIBUTE

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

DWORD PrintTokenGroups(HANDLE tokenHandle, TOKEN_INFORMATION_CLASS infoClass)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> buffer;
    PTOKEN_GROUPS groups;

    if (infoClass != TokenGroups && infoClass != TokenRestrictedSids)
    {
        return ERROR_INVALID_PARAMETER;
    }

    error = GetTokenInformation(tokenHandle, infoClass, buffer);

    if (error == ERROR_SUCCESS)
    {
        groups = (PTOKEN_GROUPS)buffer.get();

        for (DWORD i = 0; i < groups->GroupCount; i++)
        {
            std::wcout << STRING(infoClass) << L"[" << i << L"]:" << std::endl;
            PrintSidAndAttributes(groups->Groups[i]);
        }
    }
    else
    {
        std::wcout << L"Failed to get " << STRING(infoClass) << L" info, error " << error << std::endl;
    }

    return error;
}

DWORD GetPrivilegeName(PLUID luid, std::wstring& luidName)
{
    DWORD error = ERROR_SUCCESS;
    DWORD length = 0;

    if (LookupPrivilegeNameW(nullptr, luid, nullptr, &length))
    {
        std::wcout << L"LookupPrivilegeName succeeded unexpectedly, length " << length << std::endl;
        error = ERROR_BAD_ARGUMENTS;
        return error;
    }

    error = GetLastError();

    if (error != ERROR_INSUFFICIENT_BUFFER)
    {
        std::wcout << L"LookupPrivilegeName failed to get the required length, error " << error << std::endl;
        return error;
    }

    luidName.resize(length + 1);

    if (!LookupPrivilegeNameW(nullptr, luid, const_cast<wchar_t*>(luidName.c_str()), &length))
    {
        error = GetLastError();
        std::wcout << L"LookupPrivilegeName failed with error " << error << std::endl;
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
        std::wcout << L"Failed to get TokenGroups info, error " << error << std::endl;
    }

    return error;
}

DWORD PrintTokenOwner(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> buffer;
    PTOKEN_OWNER owner;
    LPWSTR sid = nullptr;

    error = GetTokenInformation(tokenHandle, TokenOwner, buffer);

    if (error == ERROR_SUCCESS)
    {
        owner = (PTOKEN_OWNER)buffer.get();

        if (ConvertSidToStringSidW(owner->Owner, &sid))
        {
            std::wcout << L"TokenOwner: " << std::wstring(sid) << std::endl;

            if (LocalFree(sid) != NULL)
            {
                std::wcout << L"LocalFree failed with error " << GetLastError() << std::endl;
            }
        }
        else
        {
            error = GetLastError();
            std::wcout << L"TokenOwner: failed to convert, error " << error << std::endl;
        }
    }
    else
    {
        error = GetLastError();
        std::wcout << L"TokenOwner: failed to get, error " << error << std::endl;
    }

    return error;
}

DWORD PrintTokenPrimaryGroup(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> buffer;
    PTOKEN_PRIMARY_GROUP primaryGroup;
    LPWSTR sid = nullptr;

    error = GetTokenInformation(tokenHandle, TokenPrimaryGroup, buffer);

    if (error == ERROR_SUCCESS)
    {
        primaryGroup = (PTOKEN_PRIMARY_GROUP)buffer.get();

        if (ConvertSidToStringSidW(primaryGroup->PrimaryGroup, &sid))
        {
            std::wcout << L"TokenPrimaryGroup: " << std::wstring(sid) << std::endl;

            if (LocalFree(sid) != NULL)
            {
                std::wcout << L"LocalFree failed with error " << GetLastError() << std::endl;
            }
        }
        else
        {
            error = GetLastError();
            std::wcout << L"TokenPrimaryGroup: failed to convert, error " << error << std::endl;
        }
    }
    else
    {
        error = GetLastError();
        std::wcout << L"TokenPrimaryGroup: failed to get, error " << error << std::endl;
    }

    return error;
}

#define map_entry(x) {x, L#x}

const std::map<int, std::wstring> AceType =
{
    map_entry(ACCESS_ALLOWED_ACE_TYPE),
    map_entry(ACCESS_DENIED_ACE_TYPE),
    map_entry(SYSTEM_AUDIT_ACE_TYPE),
    map_entry(SYSTEM_ALARM_ACE_TYPE),
    map_entry(ACCESS_ALLOWED_COMPOUND_ACE_TYPE),
    map_entry(ACCESS_ALLOWED_OBJECT_ACE_TYPE),
    map_entry(ACCESS_DENIED_OBJECT_ACE_TYPE),
    map_entry(SYSTEM_AUDIT_OBJECT_ACE_TYPE),
    map_entry(SYSTEM_ALARM_OBJECT_ACE_TYPE),
    map_entry(ACCESS_ALLOWED_CALLBACK_ACE_TYPE),
    map_entry(ACCESS_DENIED_CALLBACK_ACE_TYPE),
    map_entry(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE),
    map_entry(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE),
    map_entry(SYSTEM_AUDIT_CALLBACK_ACE_TYPE),
    map_entry(SYSTEM_ALARM_CALLBACK_ACE_TYPE),
    map_entry(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE),
    map_entry(SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE),
    map_entry(SYSTEM_MANDATORY_LABEL_ACE_TYPE),
    map_entry(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE),
    map_entry(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE),
    map_entry(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE),
    map_entry(SYSTEM_ACCESS_FILTER_ACE_TYPE)
};

DWORD PrintAccessMask(ACCESS_MASK mask)
{
    DWORD error = ERROR_SUCCESS;
    std::wcout << L"AccessMask: 0x" << std::hex << mask << std::dec << L" ";

#define OUT_MASK(x) \
    if (mask & (x)) \
    { \
        std::wcout << L"|" << #x; \
    }

    // Generic rights
    OUT_MASK(GENERIC_READ);
    OUT_MASK(GENERIC_WRITE);
    OUT_MASK(GENERIC_EXECUTE);
    OUT_MASK(GENERIC_ALL);
    OUT_MASK(MAXIMUM_ALLOWED);
    OUT_MASK(ACCESS_SYSTEM_SECURITY);
    // Standard rights
    OUT_MASK(SYNCHRONIZE);
    OUT_MASK(WRITE_OWNER);
    OUT_MASK(WRITE_DAC);
    OUT_MASK(READ_CONTROL);
    OUT_MASK(DELETE);

#undef OUT_MASK

    std::wcout << std::endl;
    return error;
}

DWORD PrintSid(const PSID sid)
{
    DWORD error = ERROR_SUCCESS;
    LPWSTR strSid = nullptr;

    if (sid == nullptr)
    {
        error = ERROR_INVALID_SID;
        std::wcout << L"Sid: nullptr, error " << error << std::endl;
    }
    else if (ConvertSidToStringSidW(const_cast<PSID>(sid), &strSid))
    {
        std::wcout << L"Sid: " << std::wstring(strSid) << std::endl;

        if (LocalFree(strSid) != NULL)
        {
            std::wcout << L"LocalFree failed with error " << GetLastError() << std::endl;
        }
    }
    else
    {
        error = GetLastError();
        std::wcout << L"Sid: failed to convert, error " << error << std::endl;
    }

    return error;
}

DWORD PrintAccessAllowedAce(const PACCESS_ALLOWED_ACE ace)
{
    DWORD error = ERROR_SUCCESS;

    if (ace == nullptr)
    {
        return ERROR_INVALID_ACL;
    }

    PrintAccessMask(ace->Mask);
    PrintSid(&ace->SidStart);
    return error;
}

DWORD PrintAccessAllowedCallbackAce(const PACCESS_ALLOWED_CALLBACK_ACE ace)
{
    DWORD error = ERROR_SUCCESS;

    if (ace == nullptr)
    {
        return ERROR_INVALID_ACL;
    }

    PrintAccessMask(ace->Mask);
    PrintSid(&ace->SidStart);
    return error;
}

DWORD PrintAcl(const PACL acl)
{
    DWORD error = ERROR_SUCCESS;
    ACL_REVISION_INFORMATION aclRevision = { 0 };
    ACL_SIZE_INFORMATION aclSize = { 0 };
    LPVOID ace = nullptr;
    PACE_HEADER aceHeader = nullptr;

    if (acl == nullptr)
    {
        return ERROR_INVALID_ACL;
    }

    if (GetAclInformation(const_cast<PACL>(acl), &aclRevision, sizeof(ACL_REVISION_INFORMATION), AclRevisionInformation))
    {
        std::wcout << L"AclRevision: " << aclRevision.AclRevision;
    }
    else
    {
        error = GetLastError();
        std::wcout << L"AclRevision: error " << error;
    }

    if (GetAclInformation(const_cast<PACL>(acl), &aclSize, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation))
    {
        std::wcout << L", AclCount: " << aclSize.AceCount << L", AclBytesInUse: " << aclSize.AclBytesInUse << L", AclBytesFree: " << aclSize.AclBytesFree << std::endl;
    }
    else
    {
        error = GetLastError();
        std::wcout << L", AclSize: error " << error << std::endl;
    }

    for (DWORD i = 0; i < aclSize.AceCount; i++)
    {
        std::wcout << L"ACE[" << i << L"]:" << std::endl;

        if (GetAce(const_cast<PACL>(acl), i, &ace))
        {
            aceHeader = (PACE_HEADER)ace;
            if (AceType.find(aceHeader->AceType) == AceType.end())
            {
                std::wcout << L"Type: " << aceHeader->AceType;
            }
            else
            {
                std::wcout << L"Type: " << AceType.at(aceHeader->AceType);
            }
            std::wcout << L", Flags: 0x" << std::hex << aceHeader->AceFlags << std::dec << L" ";

#define OUT_ATTRIBUTE(x) \
        if (aceHeader->AceFlags & (x)) \
        { \
            std::wcout << L"|" << #x; \
        }

            OUT_ATTRIBUTE(FAILED_ACCESS_ACE_FLAG);
            OUT_ATTRIBUTE(SUCCESSFUL_ACCESS_ACE_FLAG);
            OUT_ATTRIBUTE(INHERITED_ACE);
            OUT_ATTRIBUTE(INHERIT_ONLY_ACE);
            OUT_ATTRIBUTE(NO_PROPAGATE_INHERIT_ACE);
            OUT_ATTRIBUTE(CONTAINER_INHERIT_ACE);
            OUT_ATTRIBUTE(OBJECT_INHERIT_ACE);

#undef OUT_ATTRIBUTE

            std::wcout << L", Size: " << aceHeader->AceSize << std::endl;
        }
        else
        {
            error = GetLastError();
            std::wcout << L"GetAce failed with error " << error << std::endl;
        }

        switch (aceHeader->AceType)
        {
        case ACCESS_ALLOWED_ACE_TYPE:
            PrintAccessAllowedAce((PACCESS_ALLOWED_ACE)ace);
            break;
        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
            PrintAccessAllowedCallbackAce((PACCESS_ALLOWED_CALLBACK_ACE)ace);
            break;
        default:
            break;
        }
    }

    return error;
}

DWORD PrintTokenDefaultDacl(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> buffer;
    PTOKEN_DEFAULT_DACL defaultDacl;

    error = GetTokenInformation(tokenHandle, TokenDefaultDacl, buffer);

    if (error == ERROR_SUCCESS)
    {
        defaultDacl = (PTOKEN_DEFAULT_DACL)buffer.get();
        std::wcout << L"TokenDefaultDacl:" << std::endl;
        PrintAcl(defaultDacl->DefaultDacl);
    }
    else
    {
        error = GetLastError();
        std::wcout << L"TokenDefaultDacl: failed to get, error " << error << std::endl;
    }

    return error;
}

DWORD PrintTokenSource(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> buffer;
    PTOKEN_SOURCE source;

    error = GetTokenInformation(tokenHandle, TokenSource, buffer);

    if (error == ERROR_SUCCESS)
    {
        source = (PTOKEN_SOURCE)buffer.get();
        std::wcout << L"TokenSource:" << std::endl;
        std::wcout << L"Name: " << source->SourceName << L", Luid: 0x" << std::hex << source->SourceIdentifier.HighPart << L":" << source->SourceIdentifier.LowPart << std::dec << std::endl;
    }
    else
    {
        error = GetLastError();
        std::wcout << L"TokenSource: failed to get, error " << error << std::endl;
    }

    return error;
}

DWORD PrintTokenType(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> buffer;
    PTOKEN_TYPE type;

    error = GetTokenInformation(tokenHandle, TokenType, buffer);

    if (error == ERROR_SUCCESS)
    {
        type = (PTOKEN_TYPE)buffer.get();
        std::wcout << L"TokenType: ";
        switch (*type)
        {
        case TokenPrimary:
            std::wcout << L"TokenPrimary" << std::endl;
            break;
        case TokenImpersonation:
            std::wcout << L"TokenImpersonation" << std::endl;
            break;
        default:
            std::wcout << L"Unknown" << std::endl;
            error = ERROR_INVALID_TOKEN;
            break;
        }
    }
    else
    {
        error = GetLastError();
        std::wcout << L"TokenType: failed to get, error " << error << std::endl;
    }

    return error;
}

DWORD PrintTokenImpersonationLevel(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> buffer;
    PSECURITY_IMPERSONATION_LEVEL level;

    error = GetTokenInformation(tokenHandle, TokenImpersonationLevel, buffer);

    if (error == ERROR_SUCCESS)
    {
        level = (PSECURITY_IMPERSONATION_LEVEL)buffer.get();
        std::wcout << L"TokenImpersonationLevel: " << *level << std::endl;
    }
    else
    {
        error = GetLastError();
        std::wcout << L"TokenImpersonationLevel: failed to get, error " << error << std::endl;
    }

    return error;
}

DWORD FileTimeToSystemTimeString(const LARGE_INTEGER &fileTime, std::wstring& systemTime)
{
    DWORD error = ERROR_SUCCESS;
    FILETIME ft;
    SYSTEMTIME st;
    std::wostringstream oss;

    ft.dwHighDateTime = fileTime.HighPart;
    ft.dwLowDateTime = fileTime.LowPart;

    if (FileTimeToSystemTime(&ft, &st))
    {
        oss << std::setfill(L'0') << st.wYear << L"-" << std::setw(2) << st.wMonth << L"-" << std::setw(2) << st.wDay << L" " << std::setw(2) << st.wHour << L":" << std::setw(2) << st.wMinute << L":" << std::setw(2) << st.wSecond << L'.' << std::setw(3) << st.wMilliseconds;
        systemTime = oss.str();
    }
    else
    {
        error = GetLastError();
        std::wcout << L"FileTimeToSystemTimeString(" << fileTime.QuadPart << L") failed with error " << error << std::endl;
    }

    return error;
}

DWORD PrintTokenStatistics(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> buffer;
    PTOKEN_STATISTICS stat;

    error = GetTokenInformation(tokenHandle, TokenStatistics, buffer);

    if (error == ERROR_SUCCESS)
    {
        stat = (PTOKEN_STATISTICS)buffer.get();
        std::wcout << L"TokenStatistics:" << std::endl;
        std::wcout << L"TokenId: 0x" << std::hex << stat->TokenId.HighPart << L":" << stat->TokenId.LowPart << std::dec << L", ";
        std::wcout << L"AuthenticationId: 0x" << std::hex << stat->AuthenticationId.HighPart << L":" << stat->AuthenticationId.LowPart << std::dec << L", ";
        
        std::wcout << L"ExpirationTime: 0x" << std::hex << stat->ExpirationTime.QuadPart << std::dec << L"[";
        std::wstring expirationTime;
        error = FileTimeToSystemTimeString(stat->ExpirationTime, expirationTime);
        if (error == ERROR_SUCCESS)
        {
            std::wcout << expirationTime;
        }
        else
        {
            std::wcout << L"Invalid";
        }
        std::wcout << L"]" << std::endl;

        std::wcout << L"ImpersonationLevel: " << stat->ImpersonationLevel << std::endl;

        std::wcout << L"Dynamic[Charged|Available]: [" << stat->DynamicCharged << L"|" << stat->DynamicAvailable << L"]" << std::endl;
        std::wcout << L"[Group|Privilege]Count: [" << stat->GroupCount << L"|" << stat->PrivilegeCount << L"]" << std::endl;

        std::wcout << L"ModifiedId: 0x" << std::hex << stat->ModifiedId.HighPart << L":" << stat->ModifiedId.LowPart << std::dec << std::endl;
    }
    else
    {
        error = GetLastError();
        std::wcout << L"TokenStatistics: failed to get, error " << error << std::endl;
    }

    return error;
}

DWORD PrintTokenSessionId(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> buffer;
    PDWORD sessionId;

    error = GetTokenInformation(tokenHandle, TokenSessionId, buffer);

    if (error == ERROR_SUCCESS)
    {
        sessionId = (PDWORD)buffer.get();
        std::wcout << L"TokenSessionId: " << *sessionId << std::endl;
    }
    else
    {
        error = GetLastError();
        std::wcout << L"TokenSessionId: failed to get, error " << error << std::endl;
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
        PrintTokenGroups(tokenHandle, TokenGroups);
        PrintTokenPrivileges(tokenHandle);
        PrintTokenOwner(tokenHandle);
        PrintTokenPrimaryGroup(tokenHandle);
        PrintTokenDefaultDacl(tokenHandle);
        PrintTokenSource(tokenHandle);
        PrintTokenType(tokenHandle);
        PrintTokenImpersonationLevel(tokenHandle);
        PrintTokenStatistics(tokenHandle);
        PrintTokenGroups(tokenHandle, TokenRestrictedSids);
        PrintTokenSessionId(tokenHandle);

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