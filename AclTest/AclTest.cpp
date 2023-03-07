#include <Windows.h>
#include <AclAPI.h>
#include <sddl.h>
#include <iomanip>
#include <iostream>
#include <sstream>

#define RETURN_IF_FAILED(e) \
    { \
        DWORD e2 = (e); \
        if (e2 != ERROR_SUCCESS) \
        { \
            std::wcerr << L"[ERROR] " << __FUNCTION__ << L" returns " << e2 << L" at " << __FILE__ << L" line " << __LINE__ << std::endl; \
            return e2; \
        } \
    }

#define RETURN_FAILURE(e) \
    { \
        DWORD e2 = (e); \
        std::wcerr << L"[ERROR] " << __FUNCTION__ << L" returns " << e2 << L" at " << __FILE__ << L" line " << __LINE__ << std::endl; \
        return e2; \
    }


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

    luidName.resize(length);

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

DWORD PrintPrivileges(const TOKEN_PRIVILEGES& privileges)
{
    for (DWORD i = 0; i < privileges.PrivilegeCount; i++)
    {
        std::wcout << L"Privileges[" << i << L"]:" << std::endl;
        PrintLuidAndAttributes(privileges.Privileges[i]);
    }

    return ERROR_SUCCESS;
}

DWORD PrintTokenPrivileges(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> buffer;

    error = GetTokenInformation(tokenHandle, TokenPrivileges, buffer);

    if (error == ERROR_SUCCESS)
    {
        std::wcout << L"TokenPrivileges:" << std::endl;
        PrintPrivileges(*((PTOKEN_PRIVILEGES)buffer.get()));
    }
    else
    {
        std::wcerr << L"Failed to get TokenPrivileges info, error " << error << std::endl;
    }

    return error;
}

DWORD SetTokenPrivilege(HANDLE tokenHandle, const std::wstring& privilege, bool enable)
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

    AdjustTokenPrivileges(
        tokenHandle,
        FALSE,
        &privileges,
        prevStateSize,
        &prevState,
        &prevStateSize);

    // AdjustTokenPrivileges returns success even when some privilegs are not set.
    // Must use GetLastError to check the result.
    error = GetLastError();

    if (error != ERROR_SUCCESS)
    {
        std::wcerr << L"Failed to set token privilege " << privilege << " to " << enable << std::endl;
        return error;
    }

    std::wcout << L"Set token privilege " << privilege << " to " << enable << std::endl;
    std::wcout << L"Token previous privilege:" << std::endl;
    PrintPrivileges(prevState);

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

class Handle
{
protected:
    HANDLE _handle;

public:
    Handle(HANDLE handle) : _handle(handle) {}
    Handle() : Handle(INVALID_HANDLE_VALUE) {}

    virtual ~Handle()
    {
        Close();
    }

    HANDLE& Get() { return _handle; }

    Handle& operator=(HANDLE handle)
    {
        _handle = handle;
        std::wcout << L"Asigned handle 0x" << std::hex << handle << std::dec << std::endl;
        return *this;
    }

    bool operator==(HANDLE handle)
    {
        std::wcout << L"Check if handle 0x" << std::hex << _handle << std::dec
            << L"==0x" << std::hex << handle << std::dec << std::endl;
        return _handle == handle;
    }

    void Attach(HANDLE handle)
    {
        if (_handle != INVALID_HANDLE_VALUE)
        {
            Close();
        }

        _handle = handle;
        std::wcout << L"Attached handle 0x" << std::hex << handle << std::dec << std::endl;
    }

    DWORD Close()
    {
        DWORD error = ERROR_SUCCESS;

        if (_handle == INVALID_HANDLE_VALUE)
        {
            std::wcout << L"Handle not opened or already closed." << std::endl;
            return error;
        }

        if (CloseHandle(_handle))
        {
            std::wcout << L"Closed handle 0x" << std::hex << _handle << std::dec << std::endl;
            _handle = INVALID_HANDLE_VALUE;
        }
        else
        {
            error = GetLastError();
            std::wcerr << L"Failed to close handle 0x" << std::hex << _handle << std::dec << std::endl;
        }

        return error;
    }
};

class ThreadToken : public Handle
{
public:
    ThreadToken()
        : Handle()
    {}

    DWORD Open()
    {
        DWORD error = ERROR_SUCCESS;
        BOOL success;

        if (_handle == INVALID_HANDLE_VALUE)
        {
            success = OpenThreadToken(
                GetCurrentThread(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE,
                TRUE,
                &_handle);

            if (success)
            {
                std::wcout << L"Opened thread token 0x" << std::hex << _handle << std::dec << std::endl;
            }
            else
            {
                error = GetLastError();
                std::wcerr << L"Failed to open thread token." << std::endl;
            }
        }
        else
        {
            std::wcout << L"Already opened thread token 0x" << std::hex << _handle << std::dec << std::endl;
        }

        return error;
    }

    DWORD Duplicate(PHANDLE duplicateTokenHandle)
    {
        DWORD error = ERROR_SUCCESS;

        if (_handle == INVALID_HANDLE_VALUE)
        {
            error = Open();
            RETURN_IF_FAILED(error);
        }

        // Cannot use DuplicateToken because its output token handle has only TOKEN_IMPERSONATE and TOKEN_QUERY access, so cannot adjust its privileges
        if (!DuplicateTokenEx(
            _handle,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_IMPERSONATE,
            NULL,
            SECURITY_IMPERSONATION_LEVEL::SecurityImpersonation,
            TOKEN_TYPE::TokenImpersonation,
            duplicateTokenHandle))
        {
            error = GetLastError();
            RETURN_FAILURE(error);
        }

        return error;
    }
};

DWORD SetTokenPrivileges(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;

    error = SetTokenPrivilege(tokenHandle, SE_BACKUP_NAME, true);
    RETURN_IF_FAILED(error);

    error = SetTokenPrivilege(tokenHandle, SE_RESTORE_NAME, true);
    RETURN_IF_FAILED(error);

    error = SetTokenPrivilege(tokenHandle, SE_SECURITY_NAME, true);
    RETURN_IF_FAILED(error);

    PrintTokenPrivileges(tokenHandle);
    return error;
}

DWORD SetThreadTokenPrivileges()
{
    DWORD error = ERROR_SUCCESS;
    ThreadToken token;

    error = token.Open();
    RETURN_IF_FAILED(error);

    error = SetTokenPrivileges(token.Get());
    RETURN_IF_FAILED(error);

    return error;
}

#define CALL_FUNC_ON_WELL_KNOWN_SIDS(F) \
F(WinNullSid); \
F(WinWorldSid); \
F(WinLocalSid); \
F(WinCreatorOwnerSid); \
F(WinCreatorGroupSid); \
F(WinCreatorOwnerServerSid); \
F(WinCreatorGroupServerSid); \
F(WinNtAuthoritySid); \
F(WinDialupSid); \
F(WinNetworkSid); \
F(WinBatchSid); \
F(WinInteractiveSid); \
F(WinServiceSid); \
F(WinAnonymousSid); \
F(WinProxySid); \
F(WinEnterpriseControllersSid); \
F(WinSelfSid); \
F(WinAuthenticatedUserSid); \
F(WinRestrictedCodeSid); \
F(WinTerminalServerSid); \
F(WinRemoteLogonIdSid); \
F(WinLogonIdsSid); \
F(WinLocalSystemSid); \
F(WinLocalServiceSid); \
F(WinNetworkServiceSid); \
F(WinBuiltinDomainSid); \
F(WinBuiltinAdministratorsSid); \
F(WinBuiltinUsersSid); \
F(WinBuiltinGuestsSid); \
F(WinBuiltinPowerUsersSid); \
F(WinBuiltinAccountOperatorsSid); \
F(WinBuiltinSystemOperatorsSid); \
F(WinBuiltinPrintOperatorsSid); \
F(WinBuiltinBackupOperatorsSid); \
F(WinBuiltinReplicatorSid); \
F(WinBuiltinPreWindows2000CompatibleAccessSid); \
F(WinBuiltinRemoteDesktopUsersSid); \
F(WinBuiltinNetworkConfigurationOperatorsSid); \
F(WinAccountAdministratorSid); \
F(WinAccountGuestSid); \
F(WinAccountKrbtgtSid); \
F(WinAccountDomainAdminsSid); \
F(WinAccountDomainUsersSid); \
F(WinAccountDomainGuestsSid); \
F(WinAccountComputersSid); \
F(WinAccountControllersSid); \
F(WinAccountCertAdminsSid); \
F(WinAccountSchemaAdminsSid); \
F(WinAccountEnterpriseAdminsSid); \
F(WinAccountPolicyAdminsSid); \
F(WinAccountRasAndIasServersSid); \
F(WinNTLMAuthenticationSid); \
F(WinDigestAuthenticationSid); \
F(WinSChannelAuthenticationSid); \
F(WinThisOrganizationSid); \
F(WinOtherOrganizationSid); \
F(WinBuiltinIncomingForestTrustBuildersSid); \
F(WinBuiltinPerfMonitoringUsersSid); \
F(WinBuiltinPerfLoggingUsersSid); \
F(WinBuiltinAuthorizationAccessSid); \
F(WinBuiltinTerminalServerLicenseServersSid); \
F(WinBuiltinDCOMUsersSid); \
F(WinBuiltinIUsersSid); \
F(WinIUserSid); \
F(WinBuiltinCryptoOperatorsSid); \
F(WinUntrustedLabelSid); \
F(WinLowLabelSid); \
F(WinMediumLabelSid); \
F(WinHighLabelSid); \
F(WinSystemLabelSid); \
F(WinWriteRestrictedCodeSid); \
F(WinCreatorOwnerRightsSid); \
F(WinCacheablePrincipalsGroupSid); \
F(WinNonCacheablePrincipalsGroupSid); \
F(WinEnterpriseReadonlyControllersSid); \
F(WinAccountReadonlyControllersSid); \
F(WinBuiltinEventLogReadersGroup); \
F(WinNewEnterpriseReadonlyControllersSid); \
F(WinBuiltinCertSvcDComAccessGroup); \
F(WinMediumPlusLabelSid); \
F(WinLocalLogonSid); \
F(WinConsoleLogonSid); \
F(WinThisOrganizationCertificateSid); \
F(WinApplicationPackageAuthoritySid); \
F(WinBuiltinAnyPackageSid); \
F(WinCapabilityInternetClientSid); \
F(WinCapabilityInternetClientServerSid); \
F(WinCapabilityPrivateNetworkClientServerSid); \
F(WinCapabilityPicturesLibrarySid); \
F(WinCapabilityVideosLibrarySid); \
F(WinCapabilityMusicLibrarySid); \
F(WinCapabilityDocumentsLibrarySid); \
F(WinCapabilitySharedUserCertificatesSid); \
F(WinCapabilityEnterpriseAuthenticationSid); \
F(WinCapabilityRemovableStorageSid); \
F(WinBuiltinRDSRemoteAccessServersSid); \
F(WinBuiltinRDSEndpointServersSid); \
F(WinBuiltinRDSManagementServersSid); \
F(WinUserModeDriversSid); \
F(WinBuiltinHyperVAdminsSid); \
F(WinAccountCloneableControllersSid); \
F(WinBuiltinAccessControlAssistanceOperatorsSid); \
F(WinBuiltinRemoteManagementUsersSid); \
F(WinAuthenticationAuthorityAssertedSid); \
F(WinAuthenticationServiceAssertedSid); \
F(WinLocalAccountSid); \
F(WinLocalAccountAndAdministratorSid); \
F(WinAccountProtectedUsersSid); \
F(WinCapabilityAppointmentsSid); \
F(WinCapabilityContactsSid); \
F(WinAccountDefaultSystemManagedSid); \
F(WinBuiltinDefaultSystemManagedGroupSid); \
F(WinBuiltinStorageReplicaAdminsSid); \
F(WinAccountKeyAdminsSid); \
F(WinAccountEnterpriseKeyAdminsSid); \
F(WinAuthenticationKeyTrustSid); \
F(WinAuthenticationKeyPropertyMFASid); \
F(WinAuthenticationKeyPropertyAttestationSid); \
F(WinAuthenticationFreshKeyAuthSid); \
F(WinBuiltinDeviceOwnersSid);

bool GetWellKnownSidType(const PSID sid, WELL_KNOWN_SID_TYPE& type, std::wstring &strType)
{
#define RETURN_IF_IS_WELL_KNOWN_TYPE(x) \
    if (IsWellKnownSid(sid, (x))) \
    { \
        type = x; \
        strType = L#x; \
        return true; \
    }

    CALL_FUNC_ON_WELL_KNOWN_SIDS(RETURN_IF_IS_WELL_KNOWN_TYPE);

#undef RETURN_IF_IS_WELL_KNOWN_TYPE

    return false;
}

enum DeleterType
{
    None = 0,
    DeleteByteArray,
    UseFreeSid
};

class Sid
{
private:
    PSID _sid;
    DeleterType _deleter;
    LPWSTR _str;
    WELL_KNOWN_SID_TYPE _type;
    std::wstring _strType;
    bool _typeChecked;
    bool _isWellKnown;

    void CheckWellKnownSidType()
    {
        if (!_typeChecked)
        {
            _isWellKnown = GetWellKnownSidType(_sid, _type, _strType);
            _typeChecked = true;
        }
    }

public:
    Sid(PSID sid, DeleterType deleter = DeleterType::None)
        : _sid(sid), _deleter(deleter), _str(nullptr), _type(WinNullSid), _typeChecked(false), _isWellKnown(false)
    {}

    Sid() : Sid(nullptr) {}

    ~Sid()
    {
        Free();
    }

    PSID& Get() { return _sid; }

    void SetDeleterType(DeleterType deleter)
    {
        _deleter = deleter;
    }

    void Attach(PSID sid, DeleterType deleter = DeleterType::None)
    {
        if (_sid != sid)
        {
            Free();
            _sid = sid;
            _deleter = deleter;
        }
    }

    std::wstring Str()
    {
        DWORD error = ERROR_SUCCESS;

        if (_str == nullptr)
        {
            if (!ConvertSidToStringSidW(_sid, &_str))
            {
                error = GetLastError();
                std::wcerr << L"ConvertSidToStringSidW(0x" << std::hex << _sid << std::dec << L") failed, error=" << error << std::endl;
            }
        }

        return std::wstring(_str);
    }

    bool IsWellKnown()
    {
        CheckWellKnownSidType();
        return _isWellKnown;
    }

    WELL_KNOWN_SID_TYPE WellKnownSidType()
    {
        CheckWellKnownSidType();
        return _type;
    }

    std::wstring WellKnownSidTypeString()
    {
        CheckWellKnownSidType();
        return _strType;
    }

    DWORD Free()
    {
        DWORD error = ERROR_SUCCESS;

        if (_sid != nullptr)
        {
            switch (_deleter)
            {
            case DeleterType::DeleteByteArray:
                delete[] _sid;
                break;
            case DeleterType::UseFreeSid:
                if (::FreeSid(_sid) != nullptr)
                {
                    error = GetLastError();
                    RETURN_FAILURE(error);
                }
                break;
            default:
                break;
            }

            _sid = nullptr;
            _deleter = DeleterType::None;
        }

        if (_str != nullptr)
        {
            if (LocalFree(_str) != nullptr)
            {
                error = GetLastError();
                RETURN_FAILURE(error);
            }

            _str = nullptr;
        }

        _type = WinNullSid;
        _strType.clear();
        _typeChecked = false;
        _isWellKnown = false;

        return error;
    }

    void Print()
    {
        std::wcout << Str() << L"[IsWellKnown=" << IsWellKnown();
        if (_isWellKnown)
        {
            std::wcout << L"|Type=" << _type << L"|" << _strType;
        }
        std::wcout << L"]" << std::endl;
    }
};

DWORD CreateWellKnownSid(WELL_KNOWN_SID_TYPE type, Sid& sid, PSID domainSid = nullptr)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> psid;
    DWORD size = 0;

    if (CreateWellKnownSid(type, domainSid, nullptr, &size))
    {
        error = ERROR_BAD_ARGUMENTS;
        RETURN_FAILURE(error);
    }

    psid.reset(new byte[size]);

    if (!CreateWellKnownSid(type, domainSid, psid.get(), &size))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    sid.Attach(static_cast<PSID>(psid.get()), DeleterType::DeleteByteArray);
    psid.release();

    return error;
}

DWORD CreateSid(
    Sid& sid,
    const SID_IDENTIFIER_AUTHORITY& authority,
    BYTE subAuthorityCount,
    DWORD subAuthority0,
    DWORD subAuthority1 = 0,
    DWORD subAuthority2 = 0,
    DWORD subAuthority3 = 0,
    DWORD subAuthority4 = 0,
    DWORD subAuthority5 = 0,
    DWORD subAuthority6 = 0,
    DWORD subAuthority7 = 0)
{
    DWORD error = ERROR_SUCCESS;
    PSID psid = nullptr;

    if (!AllocateAndInitializeSid(
        const_cast<PSID_IDENTIFIER_AUTHORITY>(&authority),
        subAuthorityCount,
        subAuthority0,
        subAuthority1,
        subAuthority2,
        subAuthority3,
        subAuthority4,
        subAuthority5,
        subAuthority6,
        subAuthority7,
        &psid))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    sid.Attach(psid, DeleterType::UseFreeSid);
    return error;
}

DWORD CreateRandomSid(
    Sid& sid,
    const SID_IDENTIFIER_AUTHORITY& authority,
    BYTE subAuthorityCount = 0,
    DWORD subAuthority0 = 0,
    DWORD subAuthority1 = 0,
    DWORD subAuthority2 = 0,
    DWORD subAuthority3 = 0,
    DWORD subAuthority4 = 0,
    DWORD subAuthority5 = 0,
    DWORD subAuthority6 = 0,
    DWORD subAuthority7 = 0)
{
    DWORD error = ERROR_SUCCESS;
    BYTE count = 0;
    const BYTE maxCount = 8;

    if (subAuthorityCount == 0)
    {
        subAuthorityCount = rand() % maxCount;
    }

#define SET_SUB_AUTHORITY(x) \
    if (count++ < subAuthorityCount) \
    { \
        if (x == 0) \
        { \
            x = rand(); \
        } \
    } \
    else \
    { \
        x = 0; \
    }

    SET_SUB_AUTHORITY(subAuthority0);
    SET_SUB_AUTHORITY(subAuthority1);
    SET_SUB_AUTHORITY(subAuthority2);
    SET_SUB_AUTHORITY(subAuthority3);
    SET_SUB_AUTHORITY(subAuthority4);
    SET_SUB_AUTHORITY(subAuthority5);
    SET_SUB_AUTHORITY(subAuthority6);
    SET_SUB_AUTHORITY(subAuthority7);

#undef SET_SUB_AUTHORITY

    error = CreateSid(
        sid,
        authority,
        subAuthorityCount,
        subAuthority0,
        subAuthority1,
        subAuthority2,
        subAuthority3,
        subAuthority4,
        subAuthority5,
        subAuthority6,
        subAuthority7);
    RETURN_IF_FAILED(error);
    return error;
}

DWORD PrintWellKnownSid(WELL_KNOWN_SID_TYPE type, PSID domainSid = nullptr)
{
    DWORD error = ERROR_SUCCESS;
    Sid sid;

    error = CreateWellKnownSid(type, sid, domainSid);
    RETURN_IF_FAILED(error);

    sid.Print();
    return error;
}

DWORD PrintWellKnownSids(PSID domainSid = nullptr)
{
    DWORD error = ERROR_SUCCESS;

#define PRINT_WELL_KNOWN_SID(x) \
    PrintWellKnownSid(x, domainSid);

    CALL_FUNC_ON_WELL_KNOWN_SIDS(PRINT_WELL_KNOWN_SID);

#undef PRINT_WELL_KNOWN_SID

    return error;
}

DWORD PrintSid(
    const SID_IDENTIFIER_AUTHORITY& authority,
    BYTE subAuthorityCount,
    DWORD subAuthority0,
    DWORD subAuthority1 = 0,
    DWORD subAuthority2 = 0,
    DWORD subAuthority3 = 0,
    DWORD subAuthority4 = 0,
    DWORD subAuthority5 = 0,
    DWORD subAuthority6 = 0,
    DWORD subAuthority7 = 0)
{
    DWORD error = ERROR_SUCCESS;
    Sid sid;

    error = CreateSid(
        sid,
        authority,
        subAuthorityCount,
        subAuthority0,
        subAuthority1,
        subAuthority2,
        subAuthority3,
        subAuthority4,
        subAuthority5,
        subAuthority6,
        subAuthority7);
    RETURN_IF_FAILED(error);

    sid.Print();
    return error;
}

DWORD PrintSids()
{
    DWORD error = ERROR_SUCCESS;

    PrintSid(SECURITY_NULL_SID_AUTHORITY, 1, SECURITY_NULL_RID);
    PrintSid(SECURITY_WORLD_SID_AUTHORITY, 1, SECURITY_NULL_RID);
    PrintSid(SECURITY_LOCAL_SID_AUTHORITY, 1, SECURITY_NULL_RID);
    PrintSid(SECURITY_CREATOR_SID_AUTHORITY, 1, SECURITY_NULL_RID);
    PrintSid(SECURITY_NON_UNIQUE_AUTHORITY, 1, SECURITY_NULL_RID);
    PrintSid(SECURITY_RESOURCE_MANAGER_AUTHORITY, 1, SECURITY_NULL_RID);

    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 1, 1);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 1);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 2, 1, 2);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 2);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 3, 1, 2, 3);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 3);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 4, 1, 2, 3, 4);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 4);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 5, 1, 2, 3, 4, 5);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 5);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 6, 1, 2, 3, 4, 5, 6);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 6);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 7, 1, 2, 3, 4, 5, 6, 7);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 7);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 8, 1, 2, 3, 4, 5, 6, 7, 8);
        sid.Print();
    }
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY, 8);
        sid.Print();
    }

    for (int i = 0; i < 20; i++)
    {
        Sid sid;
        CreateRandomSid(sid, SECURITY_NT_AUTHORITY);
        sid.Print();
    }

    return error;
}

class Acl
{
private:
    PACL _acl;
    ULONG _acesCount;
    PEXPLICIT_ACCESS_W _aces;

    DWORD Parse()
    {
        DWORD error = ERROR_SUCCESS;

        if (_aces == NULL)
        {
            error = GetExplicitEntriesFromAclW(_acl, &_acesCount, &_aces);

            if (error != ERROR_SUCCESS)
            {
                std::wcerr << L"Acl::Parse() failed, error=" << error << std::endl;
            }
        }

        return error;
    }

public:
    Acl(PACL acl) : _acl(acl), _acesCount(0), _aces(NULL) {}
    ~Acl()
    {
        Free();
    }

    ULONG AcesCount()
    {
        Parse();
        return _acesCount;
    }

    PEXPLICIT_ACCESS_W Aces()
    {
        Parse();
        return _aces;
    }

    DWORD Free()
    {
        DWORD error = ERROR_SUCCESS;

        if (_aces != NULL)
        {
            if (LocalFree(_aces) != NULL)
            {
                error = GetLastError();
                RETURN_FAILURE(error);
            }

            _aces = NULL;
        }

        _acesCount = 0;

        return error;
    }
};

std::wstring GuidToString(const GUID& guid)
{
    std::wostringstream oss;
    oss << std::hex << std::setfill(L'0') << std::setw(8) << guid.Data1
        << L"-" << std::setw(4) << guid.Data2
        << L"-" << std::setw(4) << guid.Data3
        << L"-" << std::setw(2) << guid.Data4[0] << guid.Data4[1]
        << L"-" << std::setw(2) << guid.Data4[2] << guid.Data4[3] << guid.Data4[4] << guid.Data4[5] << guid.Data4[6] << guid.Data4[7];
    return oss.str();
}

DWORD AceString(const EXPLICIT_ACCESS_W &ace, std::wstring& aceStr)
{
    DWORD error = ERROR_SUCCESS;
    std::wostringstream oss;

    oss << L"[Permissions:0x" << std::hex << ace.grfAccessPermissions << std::dec;

#define OUT_MASK(x) \
    if (ace.grfAccessPermissions & (x)) \
    { \
        oss << L"|" << #x; \
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

    OUT_MASK(FILE_WRITE_ATTRIBUTES);
    OUT_MASK(FILE_READ_ATTRIBUTES);
    OUT_MASK(FILE_DELETE_CHILD);
    OUT_MASK(FILE_EXECUTE);
    // OUT_MASK(FILE_TRAVERSE);
    OUT_MASK(FILE_WRITE_EA);
    OUT_MASK(FILE_READ_EA);
    OUT_MASK(FILE_APPEND_DATA);
    // OUT_MASK(FILE_ADD_SUBDIRECTORY);
    // OUT_MASK(FILE_CREATE_PIPE_INSTANCE);
    OUT_MASK(FILE_WRITE_DATA);
    // OUT_MASK(FILE_ADD_FILE);
    OUT_MASK(FILE_READ_DATA);
    // OUT_MASK(FILE_LIST_DIRECTORY);

#undef OUT_MASK

    oss << L"]";
    
    oss << L"[Mode:" << ace.grfAccessMode;

#define OUT_MODE(x) \
    if (ace.grfAccessMode == (x)) \
    { \
        oss << L"|" << #x; \
    }

    OUT_MODE(NOT_USED_ACCESS);
    OUT_MODE(GRANT_ACCESS);
    OUT_MODE(SET_ACCESS);
    OUT_MODE(DENY_ACCESS);
    OUT_MODE(REVOKE_ACCESS);
    OUT_MODE(SET_AUDIT_SUCCESS);
    OUT_MODE(SET_AUDIT_FAILURE);

#undef OUT_MODE

    oss << L"]";
    
    oss << L"[Inheritance:0x" << std::hex << ace.grfInheritance << std::dec;

#define OUT_INHERITANCE(x) \
    if (ace.grfInheritance & (x)) \
    { \
        oss << L"|" << #x; \
    }

    OUT_INHERITANCE(INHERITED_ACE);
    OUT_INHERITANCE(INHERIT_ONLY_ACE);
    OUT_INHERITANCE(NO_PROPAGATE_INHERIT_ACE);
    OUT_INHERITANCE(CONTAINER_INHERIT_ACE);
    OUT_INHERITANCE(OBJECT_INHERIT_ACE);

#undef OUT_INHERITANCE

    oss << L"]";
    
    oss << L"[Trustee:";

    oss << L"[pMultipleTrustee:0x" << std::hex << ace.Trustee.pMultipleTrustee << std::dec;
    oss << L"]";
    
    oss << L"[MultipleTrusteeOperation:" << ace.Trustee.MultipleTrusteeOperation << L"|";
    switch (ace.Trustee.MultipleTrusteeOperation)
    {
    case NO_MULTIPLE_TRUSTEE:
        oss << L"NO_MULTIPLE_TRUSTEE";
        break;
    case TRUSTEE_IS_IMPERSONATE:
        oss << L"TRUSTEE_IS_IMPERSONATE";
        break;
    default:
        oss << L"Unknown";
        break;
    }
    oss << L"]";
    
    oss << L"[TrusteeForm:" << ace.Trustee.TrusteeForm << L"|";
    switch (ace.Trustee.TrusteeForm)
    {
    case TRUSTEE_IS_SID:
        oss << L"TRUSTEE_IS_SID";
        break;
    case TRUSTEE_IS_NAME:
        oss << L"TRUSTEE_IS_NAME";
        break;
    case TRUSTEE_BAD_FORM:
        oss << L"TRUSTEE_BAD_FORM"; 
        break;
    case TRUSTEE_IS_OBJECTS_AND_SID:
        oss << L"TRUSTEE_IS_OBJECTS_AND_SID"; 
        break;
    case TRUSTEE_IS_OBJECTS_AND_NAME:
        oss << L"TRUSTEE_IS_OBJECTS_AND_NAME"; 
        break;
    default:
        oss << L"Unknown";
        break;
    }
    oss << L"]";
    
    oss << L"[TrusteeType:" << ace.Trustee.TrusteeType << L"|";
    switch (ace.Trustee.TrusteeType)
    {
    case TRUSTEE_IS_UNKNOWN:
        oss << L"TRUSTEE_IS_UNKNOWN";
        break;
    case TRUSTEE_IS_USER:
        oss << L"TRUSTEE_IS_USER";
        break;
    case TRUSTEE_IS_GROUP:
        oss << L"TRUSTEE_IS_GROUP";
        break;
    case TRUSTEE_IS_DOMAIN:
        oss << L"TRUSTEE_IS_DOMAIN";
        break;
    case TRUSTEE_IS_ALIAS:
        oss << L"TRUSTEE_IS_ALIAS";
        break;
    case TRUSTEE_IS_WELL_KNOWN_GROUP:
        oss << L"TRUSTEE_IS_WELL_KNOWN_GROUP";
        break;
    case TRUSTEE_IS_DELETED:
        oss << L"TRUSTEE_IS_DELETED";
        break;
    case TRUSTEE_IS_INVALID:
        oss << L"TRUSTEE_IS_INVALID";
        break;
    case TRUSTEE_IS_COMPUTER:
        oss << L"TRUSTEE_IS_COMPUTER";
        break;
    default:
        oss << L"Unknown";
        break;
    }
    oss << L"]";
    
    oss << L"[";
    switch (ace.Trustee.TrusteeForm)
    {
    case TRUSTEE_IS_SID:
        {
            Sid sid(static_cast<PSID>(ace.Trustee.ptstrName));
            oss << L"SID:" << sid.Str();
            if (sid.IsWellKnown())
            {
                oss << L"|" << sid.WellKnownSidTypeString();
            }
        }
        break;
    case TRUSTEE_IS_NAME:
        {
            std::wstring name(ace.Trustee.ptstrName);
            oss << L"NAME:" << name;
        }
        break;
    case TRUSTEE_IS_OBJECTS_AND_SID:
        {
            POBJECTS_AND_SID pos = static_cast<POBJECTS_AND_SID>(static_cast<PVOID>(ace.Trustee.ptstrName));
            oss << L"OBJECTS_AND_SID:";
            oss << L"[ObjectsPresent:" << pos->ObjectsPresent;

#define OUT_OBJECTSPRESENT(x) \
    if (pos->ObjectsPresent & (x)) \
    { \
        oss << L"|" << #x; \
    }

            OUT_OBJECTSPRESENT(ACE_OBJECT_TYPE_PRESENT);
            OUT_OBJECTSPRESENT(ACE_INHERITED_OBJECT_TYPE_PRESENT);

#undef OUT_OBJECTSPRESENT

            oss << L"][ObjectTypeGuid:" << GuidToString(pos->ObjectTypeGuid);
            oss << L"][InheritedObjectTypeGuid:" << GuidToString(pos->InheritedObjectTypeGuid);
            Sid sid(pos->pSid);
            oss << L"[Sid:" << sid.Str();
            if (sid.IsWellKnown())
            {
                oss << L"|" << sid.WellKnownSidTypeString();
            }
            oss << L"]";
        }
        break;
    case TRUSTEE_IS_OBJECTS_AND_NAME:
        {
            POBJECTS_AND_NAME_W pon = static_cast<POBJECTS_AND_NAME_W>(static_cast<PVOID>(ace.Trustee.ptstrName));
            oss << L"OBJECTS_AND_NAME:";
            oss << L"[ObjectsPresent:" << pon->ObjectsPresent;

#define OUT_OBJECTSPRESENT(x) \
    if (pon->ObjectsPresent & (x)) \
    { \
        oss << L"|" << #x; \
    }

            OUT_OBJECTSPRESENT(ACE_OBJECT_TYPE_PRESENT);
            OUT_OBJECTSPRESENT(ACE_INHERITED_OBJECT_TYPE_PRESENT);

#undef OUT_OBJECTSPRESENT

            oss << L"][ObjectTypeName:" << (pon->ObjectTypeName == nullptr ? L"NULL" : std::wstring(pon->ObjectTypeName));
            oss << L"][InheritedObjectTypeName:" << (pon->InheritedObjectTypeName == nullptr ? L"NULL" : std::wstring(pon->InheritedObjectTypeName));
            oss << L"][ObjectType:";
            switch (pon->ObjectType)
            {
            case SE_UNKNOWN_OBJECT_TYPE:
                oss << L"SE_UNKNOWN_OBJECT_TYPE";
                break;
            case SE_FILE_OBJECT:
                oss << L"SE_FILE_OBJECT";
                break;
            case SE_SERVICE:
                oss << L"SE_SERVICE";
                break;
            case SE_PRINTER:
                oss << L"SE_PRINTER";
                break;
            case SE_REGISTRY_KEY:
                oss << L"SE_REGISTRY_KEY";
                break;
            case SE_LMSHARE:
                oss << L"SE_LMSHARE";
                break;
            case SE_KERNEL_OBJECT:
                oss << L"SE_KERNEL_OBJECT";
                break;
            case SE_WINDOW_OBJECT:
                oss << L"SE_WINDOW_OBJECT";
                break;
            case SE_DS_OBJECT:
                oss << L"SE_DS_OBJECT";
                break;
            case SE_DS_OBJECT_ALL:
                oss << L"SE_DS_OBJECT_ALL";
                break;
            case SE_PROVIDER_DEFINED_OBJECT:
                oss << L"SE_PROVIDER_DEFINED_OBJECT";
                break;
            case SE_WMIGUID_OBJECT:
                oss << L"SE_WMIGUID_OBJECT";
                break;
            case SE_REGISTRY_WOW64_32KEY:
                oss << L"SE_REGISTRY_WOW64_32KEY";
                break;
            case SE_REGISTRY_WOW64_64KEY:
                oss << L"SE_REGISTRY_WOW64_64KEY";
                break;
            default:
                break;
            }
            oss << L"][Name:" << (pon->ptstrName == nullptr ? L"NULL" : std::wstring(pon->ptstrName)) << L"]";
        }
        break;
    case TRUSTEE_BAD_FORM:
        oss << L"TRUSTEE_BAD_FORM";
        break;
    default:
        oss << L"Unknown";
        break;
    }
    oss << L"]]";
    aceStr = oss.str();
    return error;
}

DWORD GetSecurityDescriptorInfo(
    const PSECURITY_DESCRIPTOR securityDescriptor,
    LPDWORD length,
    LPDWORD revision,
    PSECURITY_DESCRIPTOR_CONTROL control,
    PSID *owner,
    LPBOOL ownerDefaulted,
    PSID *group,
    LPBOOL groupDefaulted,
    PACL *dacl,
    LPBOOL daclPresent,
    LPBOOL daclDefaulted,
    PACL *sacl,
    LPBOOL saclPresent,
    LPBOOL saclDefaulted)
{
    DWORD error = ERROR_SUCCESS;
    DWORD localRevision;
    SECURITY_DESCRIPTOR_CONTROL localControl;
    BOOL localPresent;
    BOOL localDefaulted;

    if (securityDescriptor == nullptr || !IsValidSecurityDescriptor(securityDescriptor))
    {
        return ERROR_INVALID_SECURITY_DESCR;
    }

    if (length != nullptr)
    {
        *length = GetSecurityDescriptorLength(securityDescriptor);
    }

    if (revision != nullptr || control != nullptr)
    {
        if (revision == nullptr)
        {
            revision = &localRevision;
        }

        if (control == nullptr)
        {
            control = &localControl;
        }

        if (!GetSecurityDescriptorControl(
            securityDescriptor,
            control,
            revision))
        {
            error = GetLastError();
            RETURN_FAILURE(error);
        }
    }

    if (owner != nullptr)
    {
        if (ownerDefaulted == nullptr)
        {
            ownerDefaulted = &localDefaulted;
        }

        if (!GetSecurityDescriptorOwner(
            securityDescriptor,
            owner,
            ownerDefaulted))
        {
            error = GetLastError();
            RETURN_FAILURE(error);
        }
    }

    if (group != nullptr)
    {
        if (groupDefaulted == nullptr)
        {
            groupDefaulted = &localDefaulted;
        }

        if (!GetSecurityDescriptorGroup(
            securityDescriptor,
            group,
            groupDefaulted))
        {
            error = GetLastError();
            RETURN_FAILURE(error);
        }
    }

    if (dacl != nullptr)
    {
        if (daclPresent == nullptr)
        {
            daclPresent = &localPresent;
        }

        if (daclDefaulted == nullptr)
        {
            daclDefaulted = &localDefaulted;
        }

        if (!GetSecurityDescriptorDacl(
            securityDescriptor,
            daclPresent,
            dacl,
            daclDefaulted))
        {
            error = GetLastError();
            RETURN_FAILURE(error);
        }
    }

    if (sacl != nullptr)
    {
        if (saclPresent == nullptr)
        {
            saclPresent = &localPresent;
        }

        if (saclDefaulted == nullptr)
        {
            saclDefaulted = &localDefaulted;
        }

        if (!GetSecurityDescriptorSacl(
            securityDescriptor,
            saclPresent,
            sacl,
            saclDefaulted))
        {
            error = GetLastError();
            RETURN_FAILURE(error);
        }
    }

    return error;
}

class SecurityDescriptor
{
private:
    PSECURITY_DESCRIPTOR _pSecurityDescriptor;
    DWORD _length;
    DWORD _revision;
    SECURITY_DESCRIPTOR_CONTROL _control;
    PSID _pOwner;
    BOOL _ownerDefaulted;
    PSID _pGroup;
    BOOL _groupDefaulted;
    PACL _pDacl;
    BOOL _daclPresent;
    BOOL _daclDefaulted;
    PACL _pSacl;
    BOOL _saclPresent;
    BOOL _saclDefaulted;

public:
    SecurityDescriptor()
        : _pSecurityDescriptor(nullptr),
        _length(0),
        _revision(SDDL_REVISION_1),
        _control(0),
        _pOwner(nullptr),
        _ownerDefaulted(false),
        _pGroup(nullptr),
        _groupDefaulted(false),
        _pDacl(nullptr),
        _daclPresent(false),
        _daclDefaulted(false),
        _pSacl(nullptr),
        _saclPresent(false),
        _saclDefaulted(false)
    {}

    ~SecurityDescriptor()
    {
        Free();
    }

    PSECURITY_DESCRIPTOR& PSecurityDescriptor() { return _pSecurityDescriptor; }
    PSID& POwner() { return _pOwner; }
    PSID& PGroup() { return _pGroup; }
    PACL& PDacl() { return _pDacl; }
    PACL& PSacl() { return _pSacl; }

    std::wstring Str()
    {
        DWORD error = ERROR_SUCCESS;
        LPWSTR pstr = NULL;
        ULONG length = 0;
        std::wstring strSecurityDescriptor;

        if (_pSecurityDescriptor == NULL)
        {
            return strSecurityDescriptor;
        }

        if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            _pSecurityDescriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
            &pstr,
            &length))
        {
            error = GetLastError();
            std::wcerr << L"Failed to convert security descriptor 0x" << std::hex << _pSecurityDescriptor << std::dec << L" to string format, error=" << error << std::endl;
            return strSecurityDescriptor;
        }

        strSecurityDescriptor.assign(pstr, length);

        if (LocalFree(pstr) != NULL)
        {
            error = GetLastError();
            std::wcerr << L"Failed to free string security descriptor 0x" << std::hex << pstr << std::dec << std::endl;
        }

        return strSecurityDescriptor;
    }

    DWORD Set(const std::wstring& strSecurityDescriptor)
    {
        DWORD error = ERROR_SUCCESS;
        ULONG size;

        Free();

        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            strSecurityDescriptor.c_str(),
            SDDL_REVISION_1,
            &_pSecurityDescriptor,
            &size))
        {
            error = GetLastError();
            std::wcerr << L"Failed to convert security descriptor " << strSecurityDescriptor << L" to binary format, error=" << error << std::endl;
            RETURN_FAILURE(error);
        }

        error = GetSecurityDescriptorInfo(
            _pSecurityDescriptor,
            &_length,
            &_revision,
            &_control,
            &_pOwner,
            &_ownerDefaulted,
            &_pGroup,
            &_groupDefaulted,
            &_pDacl,
            &_daclPresent,
            &_daclDefaulted,
            &_pSacl,
            &_saclPresent,
            &_saclDefaulted);

        RETURN_IF_FAILED(error);
        return error;
    }

    DWORD Free()
    {
        DWORD error = ERROR_SUCCESS;

        if (_pSecurityDescriptor != nullptr)
        {
            if (LocalFree(_pSecurityDescriptor) != nullptr)
            {
                error = GetLastError();
                std::wcerr << L"Failed to free security descriptor 0x" << std::hex << _pSecurityDescriptor << std::dec << std::endl;
                return error;
            }

            std::wcout << L"Freed security descriptor 0x" << std::hex << _pSecurityDescriptor << std::dec << std::endl;

            _pSecurityDescriptor = nullptr;
            _length = 0;
            _revision = SDDL_REVISION_1;
            _control = 0;
            _pOwner = nullptr;
            _ownerDefaulted = false;
            _pGroup = nullptr;
            _groupDefaulted = false;
            _pDacl = nullptr;
            _daclPresent = false;
            _daclDefaulted = false;
            _pSacl = nullptr;
            _saclPresent = false;
            _saclDefaulted = false;
        }

        return error;
    }

    DWORD Print()
    {
        DWORD error = ERROR_SUCCESS;
        PBYTE pb;
        PWORD pw;

        error = GetSecurityDescriptorInfo(
            _pSecurityDescriptor,
            &_length,
            &_revision,
            &_control,
            &_pOwner,
            &_ownerDefaulted,
            &_pGroup,
            &_groupDefaulted,
            &_pDacl,
            &_daclPresent,
            &_daclDefaulted,
            &_pSacl,
            &_saclPresent,
            &_saclDefaulted);
        RETURN_IF_FAILED(error);

        pb = (PBYTE)_pSecurityDescriptor;
        std::wcout << L"SecurityDescriptor 0x" << std::hex << pb << std::dec << std::endl;
        std::wcout << L"  Length: " << _length << std::endl;
        std::wcout << L"  Revision: " << _revision << L"[" << pb[0] << L"]" << std::endl;
        std::wcout << L"  Sbz1: " << pb[1] << std::endl;
        pw = (PWORD)(pb + 2);
        std::wcout << L"  Control: 0x" << std::hex << _control << L"[" << *pw << L"]" << std::dec;

#define OUT_CONTROL(x) \
        if (_control & (x)) \
        { \
            std::wcout << L"|" << #x; \
        }

        OUT_CONTROL(SE_SELF_RELATIVE);
        OUT_CONTROL(SE_RM_CONTROL_VALID);
        OUT_CONTROL(SE_SACL_PROTECTED);
        OUT_CONTROL(SE_DACL_PROTECTED);
        OUT_CONTROL(SE_SACL_AUTO_INHERITED);
        OUT_CONTROL(SE_DACL_AUTO_INHERITED);
        OUT_CONTROL(SE_SACL_AUTO_INHERIT_REQ);
        OUT_CONTROL(SE_DACL_AUTO_INHERIT_REQ);
        OUT_CONTROL(SE_SACL_DEFAULTED);
        OUT_CONTROL(SE_SACL_PRESENT);
        OUT_CONTROL(SE_DACL_DEFAULTED);
        OUT_CONTROL(SE_DACL_PRESENT);
        OUT_CONTROL(SE_GROUP_DEFAULTED);
        OUT_CONTROL(SE_OWNER_DEFAULTED);

#undef OUT_CONTROL

        std::wcout << std::endl;

        std::wcout << L"  Owner: [0x" << std::hex << _pOwner << L"]" << std::dec;
        Sid ownerSid(_pOwner);
        std::wcout << ownerSid.Str();

        if (ownerSid.IsWellKnown())
        {
            std::wcout << L"|" << ownerSid.WellKnownSidTypeString();
        }

        std::wcout << std::endl;

        if (_pOwner != nullptr)
        {
            std::wcout << L"    OwnerDefaulted: " << _ownerDefaulted << std::endl;
        }

        std::wcout << L"  Group: [0x" << std::hex << _pGroup << L"]" << std::dec;
        Sid groupSid(_pGroup);
        std::wcout << groupSid.Str();

        if (groupSid.IsWellKnown())
        {
            std::wcout << L"|" << groupSid.WellKnownSidTypeString();
        }

        std::wcout << std::endl;

        if (_pGroup != nullptr)
        {
            std::wcout << L"    GroupDefaulted: " << _groupDefaulted << std::endl;
        }

        if (_daclPresent)
        {
            std::wcout << L"  Dacl: [0x" << std::hex << _pDacl << L"]" << std::dec << std::endl;
            std::wcout << L"    DaclDefaulted: " << _daclDefaulted << std::endl;
            Acl daclObj(_pDacl);
            ULONG acesCount = daclObj.AcesCount();
            std::wcout << L"    Dacl ACEs Count: " << acesCount << std::endl;
            PEXPLICIT_ACCESS_W aces = daclObj.Aces();
            for (ULONG i = 0; i < acesCount; i++)
            {
                std::wstring aceStr;
                AceString(aces[i], aceStr);
                std::wcout << L"    Dacl ACE[" << i << L"]:" << aceStr << std::endl;
            }
        }

        if (_saclPresent)
        {
            std::wcout << L"  Sacl: [0x" << std::hex << _pSacl << L"]" << std::dec << std::endl;
            std::wcout << L"    SaclDefaulted: " << _saclDefaulted << std::endl;
            Acl saclObj(_pSacl);
            std::wcout << L"    Sacl ACEs Count: " << saclObj.AcesCount() << std::endl;
            std::wcout << L"    Sacl ACEs: 0x" << std::hex << saclObj.Aces() << std::dec << std::endl;
        }

        return error;
    }
};

DWORD PrintFileSecurityDescriptor(const std::wstring& file)
{
    DWORD error = ERROR_SUCCESS;
    Handle fileHandle;
    SecurityDescriptor securityDescriptor;
    SECURITY_INFORMATION securityInfo;

    fileHandle = CreateFileW(
        file.c_str(),
        GENERIC_READ|ACCESS_SYSTEM_SECURITY|WRITE_OWNER|WRITE_DAC|READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        error = GetLastError();
        std::wcerr << L"Failed to open " << file << L", error=" << error << std::endl;
        return error;
    }

    std::wcout << L"Opened " << file << std::endl;

    securityInfo =
        OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | SACL_SECURITY_INFORMATION
        | LABEL_SECURITY_INFORMATION
        | ATTRIBUTE_SECURITY_INFORMATION
        | SCOPE_SECURITY_INFORMATION
        | PROCESS_TRUST_LABEL_SECURITY_INFORMATION
        | ACCESS_FILTER_SECURITY_INFORMATION
        | BACKUP_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION
        | PROTECTED_SACL_SECURITY_INFORMATION
        | UNPROTECTED_DACL_SECURITY_INFORMATION
        | UNPROTECTED_SACL_SECURITY_INFORMATION;

    error = GetSecurityInfo(
        fileHandle.Get(),
        SE_FILE_OBJECT,
        securityInfo,
        &securityDescriptor.POwner(),
        &securityDescriptor.PGroup(),
        &securityDescriptor.PDacl(),
        &securityDescriptor.PSacl(),
        &securityDescriptor.PSecurityDescriptor());

    if (error != ERROR_SUCCESS)
    {
        std::wcerr << L"Failed to get security info for " << file << std::endl;
        return error;
    }

    std::wcout << L"Security descriptor is:\"" << securityDescriptor.Str() << L"\"" << std::endl;

    std::wcout << L"Dump:" << std::endl;
    securityDescriptor.Print();

    return error;
}

DWORD PrintSidAndAttributes(const SID_AND_ATTRIBUTES& sa)
{
    DWORD error = ERROR_SUCCESS;
    Sid sid;

    sid.Attach(sa.Sid);
    sid.Print();

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
        std::wcout << L"TokenUser:" << std::endl;
        PrintSidAndAttributes(user->User);
    }
    else
    {
        std::wcout << L"Failed to get TokenUser info, error " << error << std::endl;
    }

    return error;
}

DWORD SetTokenUser(HANDLE tokenHandle)
{

}

void Usage(int argc, wchar_t * argv[])
{
    std::wcout << L"Usage:" << std::endl;
    std::wcout << argv[0] << L" token" << std::endl;
    std::wcout << argv[0] << L" file <file path>" << std::endl;
    std::wcout << argv[0] << L" sd <security descriptor>" << std::endl;
    std::wcout << argv[0] << L" sid" << std::endl;
    std::wcout << argv[0] << L" sid wellknown" << std::endl;
    std::wcout << argv[0] << L" sid wellknown <type>" << std::endl;
    std::wcout << argv[0] << L" sid <sid>" << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
    DWORD error = ERROR_SUCCESS;

    if (argc < 2)
    {
        Usage(argc, argv);
        return ERROR_BAD_ARGUMENTS;
    }

    std::wstring command(argv[1]);

    if (command == L"token")
    {
        Impersonator impersonator;
        error = impersonator.BeginImpersonateSelf();
        RETURN_IF_FAILED(error);

        ThreadToken threadToken;
        ThreadToken duplicateToken;

        error = threadToken.Open();
        RETURN_IF_FAILED(error);

        std::wcout << L"Duplicate thread token =======>" << std::endl;
        error = threadToken.Duplicate(&duplicateToken.Get());
        RETURN_IF_FAILED(error);

        error = SetTokenPrivileges(duplicateToken.Get());
        RETURN_IF_FAILED(error);

        std::wcout << L"Thread token privileges =======>" << std::endl;
        PrintTokenPrivileges(threadToken.Get());

        std::wcout << L"Duplicate token privileges =======>" << std::endl;
        PrintTokenPrivileges(duplicateToken.Get());

        std::wcout << L"Thread token user =======>" << std::endl;
        PrintTokenUser(threadToken.Get());
        std::wcout << L"Duplicate token user =======>" << std::endl;
        PrintTokenUser(duplicateToken.Get());
    }
    else if (command == L"file")
    {
        if (argc < 3)
        {
            Usage(argc, argv);
            return ERROR_BAD_ARGUMENTS;
        }

        Impersonator impersonator;
        error = impersonator.BeginImpersonateSelf();
        RETURN_IF_FAILED(error);

        error = SetThreadTokenPrivileges();
        RETURN_IF_FAILED(error);

        error = PrintFileSecurityDescriptor(argv[2]);
    }
    else if (command == L"sd")
    {
        if (argc < 3)
        {
            Usage(argc, argv);
            return ERROR_BAD_ARGUMENTS;
        }

        std::wstring securityDescriptorString(argv[2]);
        std::wcout << L"Security descriptor is:\"" << securityDescriptorString << L"\"" << std::endl;

        SecurityDescriptor securityDescriptor;
        securityDescriptor.Set(securityDescriptorString);

        std::wcout << L"Dump:" << std::endl;
        securityDescriptor.Print();
    }
    else if (command == L"sid")
    {
        if (argc == 2)
        {
            error = PrintSids();
        }
        else
        {
            command.assign(argv[2]);

            if (command == L"wellknown")
            {
                if (argc == 3)
                {
                    error = PrintWellKnownSids();
                }
                else
                {
                    WELL_KNOWN_SID_TYPE type = static_cast<WELL_KNOWN_SID_TYPE>(_wtoi(argv[3]));
                    error = PrintWellKnownSid(type);
                }
            }
        }
    }
    else
    {
        Usage(argc, argv);
        error = ERROR_BAD_ARGUMENTS;
    }

    RETURN_IF_FAILED(error);
    return error;
}