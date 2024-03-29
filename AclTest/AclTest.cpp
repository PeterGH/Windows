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

GENERIC_MAPPING FileGenericMapping = {
    FILE_GENERIC_READ,
    FILE_GENERIC_WRITE,
    FILE_GENERIC_EXECUTE,
    FILE_ALL_ACCESS
};

const SECURITY_INFORMATION SecurityDescriptorSecurityInformation
= OWNER_SECURITY_INFORMATION
| GROUP_SECURITY_INFORMATION
| DACL_SECURITY_INFORMATION
| SACL_SECURITY_INFORMATION
| LABEL_SECURITY_INFORMATION
| ATTRIBUTE_SECURITY_INFORMATION
| SCOPE_SECURITY_INFORMATION
| PROCESS_TRUST_LABEL_SECURITY_INFORMATION
| ACCESS_FILTER_SECURITY_INFORMATION
| PROTECTED_DACL_SECURITY_INFORMATION
| PROTECTED_SACL_SECURITY_INFORMATION
| UNPROTECTED_DACL_SECURITY_INFORMATION
| UNPROTECTED_SACL_SECURITY_INFORMATION;
// BACKUP_SECURITY_INFORMATION

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

bool GetWellKnownSidType(const PSID sid, WELL_KNOWN_SID_TYPE& type, std::wstring& strType)
{
#define RETURN_IF_IS_WELL_KNOWN_TYPE(x) \
    if (::IsWellKnownSid(sid, (x))) \
    { \
        type = x; \
        strType = L#x; \
        return true; \
    }

    CALL_FUNC_ON_WELL_KNOWN_SIDS(RETURN_IF_IS_WELL_KNOWN_TYPE);

#undef RETURN_IF_IS_WELL_KNOWN_TYPE

    return false;
}

DWORD SetSid(
    PSID sid,
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
    DWORD index = 0;
    PDWORD subAuthority = nullptr;

    if (!InitializeSid(sid, const_cast<PSID_IDENTIFIER_AUTHORITY>(&authority), subAuthorityCount))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

#define SET_SUB_AUTHORITY(x) \
    if (index < subAuthorityCount) \
    { \
        subAuthority = GetSidSubAuthority(sid, index); \
        *subAuthority = x; \
    } \
    index++;

    SET_SUB_AUTHORITY(subAuthority0);
    SET_SUB_AUTHORITY(subAuthority1);
    SET_SUB_AUTHORITY(subAuthority2);
    SET_SUB_AUTHORITY(subAuthority3);
    SET_SUB_AUTHORITY(subAuthority4);
    SET_SUB_AUTHORITY(subAuthority5);
    SET_SUB_AUTHORITY(subAuthority6);
    SET_SUB_AUTHORITY(subAuthority7);

#undef SET_SUB_AUTHORITY

    return error;
}

DWORD CreateSid(
    std::unique_ptr<byte[]>& sid,
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
    DWORD length = GetSidLengthRequired(subAuthorityCount);
    sid.reset(new byte[length]);
    error = SetSid(
        static_cast<PSID>(sid.get()),
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

DWORD GetTokenInformation(HANDLE tokenHandle, TOKEN_INFORMATION_CLASS infoClass, std::unique_ptr<byte[]>& info)
{
    DWORD error = ERROR_SUCCESS;
    DWORD infoLength = 0;

    if (::GetTokenInformation(tokenHandle, infoClass, nullptr, 0, &infoLength))
    {
        std::wcerr << L"GetTokenInformation succeeded unexpectedly, infoLength " << infoLength << std::endl;
        return ERROR_BAD_ARGUMENTS;
    }

    info.reset(new byte[infoLength]);

    if (!::GetTokenInformation(tokenHandle, infoClass, info.get(), infoLength, &infoLength))
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

    if (::LookupPrivilegeNameW(nullptr, luid, nullptr, &length))
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

    if (!::LookupPrivilegeNameW(nullptr, luid, const_cast<wchar_t*>(luidName.c_str()), &length))
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
        std::wcout << L"Privileges[" << i << L"]: ";
        PrintLuidAndAttributes(privileges.Privileges[i]);
    }

    return ERROR_SUCCESS;
}

DWORD SetTokenPrivilege(HANDLE tokenHandle, const std::wstring& privilege, bool enable)
{
    DWORD error = ERROR_SUCCESS;
    LUID luid;
    TOKEN_PRIVILEGES privileges;
    TOKEN_PRIVILEGES prevState;
    DWORD prevStateSize;

    if (!::LookupPrivilegeValueW(nullptr, privilege.c_str(), &luid))
    {
        error = GetLastError();
        std::wcerr << L"Failed to look up privilege " << privilege << ", error=" << error << std::endl;
        return error;
    }

    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = (enable ? SE_PRIVILEGE_ENABLED : 0);

    prevStateSize = sizeof(prevState);

    ::AdjustTokenPrivileges(
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

DWORD AccessCheck(PSECURITY_DESCRIPTOR securityDescriptor, HANDLE tokenHandle, DWORD desiredAccess = MAXIMUM_ALLOWED)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> privilegeSet;
    DWORD privilegeSetLength = 0;
    DWORD grantedAccess = 0;
    BOOL accessStatus = false;

    if (!::AccessCheck(
        securityDescriptor,
        tokenHandle,
        desiredAccess,
        &FileGenericMapping,
        nullptr,
        &privilegeSetLength,
        &grantedAccess,
        &accessStatus) || !accessStatus)
    {
        error = GetLastError();

        if (error == ERROR_INSUFFICIENT_BUFFER)
        {
            privilegeSet.reset(new byte[privilegeSetLength]);

            if (privilegeSet != nullptr)
            {
                if (!::AccessCheck(
                    securityDescriptor,
                    tokenHandle,
                    desiredAccess,
                    &FileGenericMapping,
                    (PPRIVILEGE_SET)privilegeSet.get(),
                    &privilegeSetLength,
                    &grantedAccess,
                    &accessStatus) || !accessStatus)
                {
                    error = GetLastError();
                }
                else
                {
                    error = ERROR_SUCCESS;
                }
            }
            else
            {
                error = ERROR_OUTOFMEMORY;
            }
        }
    }
    RETURN_IF_FAILED(error);

    std::wcout << L"Max allowed access is 0x" << std::hex << grantedAccess << std::dec << std::endl;
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
            success = ::ImpersonateSelf(SecurityImpersonation);

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
            success = ::RevertToSelf();

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

enum class AllocType
{
    None = 0,
    UseNewByteArray,
    UseHeapAlloc,
    UseLocalAlloc,
    UseAllocateAndInitializeSid
};

template<class T> class Pointer
{
protected:
    T* _pointer;
    AllocType _allocType;

public:
    Pointer(T* pointer = nullptr, AllocType allocType = AllocType::None)
        : _pointer(pointer), _allocType(allocType)
    {}

    virtual ~Pointer()
    {
        Free();
    }

    T*& Get() { return _pointer; }

    void SetAllocType(AllocType allocType)
    {
        _allocType = allocType;
    }

    void Attach(T* pointer, AllocType allocType = AllocType::None)
    {
        Free();
        _pointer = pointer;
        _allocType = allocType;
    }

    Pointer& operator=(T* pointer)
    {
        Attach(pointer);
        return *this;
    }

    bool operator==(T* pointer)
    {
        return _pointer == pointer;
    }

    bool operator!=(T* pointer)
    {
        return _pointer != pointer;
    }

    T*& operator->() { return _pointer; }

    template<typename X = T>
    typename std::enable_if<!std::is_void<X>::value>::type&
        operator*() { return *_pointer; }

    virtual DWORD Alloc(size_t byteCount)
    {
        DWORD error = ERROR_SUCCESS;

        if (_pointer == nullptr)
        {
            switch (_allocType)
            {
            case AllocType::UseNewByteArray:
            {
                byte* p = new byte[byteCount];
                if (p == nullptr)
                {
                    error = ERROR_NOT_ENOUGH_MEMORY;
                }
                else
                {
                    _pointer = (T*)(p);
                }
            }
            break;
            case AllocType::UseHeapAlloc:
            {
                LPVOID p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, byteCount);
                if (p == nullptr)
                {
                    // HeapAlloc does not call SetLastError() on failures
                    error = ERROR_NOT_ENOUGH_MEMORY;
                }
                else
                {
                    _pointer = static_cast<T*>(p);
                }
            }
            break;
            case AllocType::UseLocalAlloc:
            {
                HLOCAL p = LocalAlloc(LPTR, byteCount);
                if (p == nullptr)
                {
                    error = GetLastError();
                }
                else
                {
                    _pointer = static_cast<T*>(p);
                }

            }
            break;
            case AllocType::UseAllocateAndInitializeSid:
            {
                error = ERROR_NOT_SUPPORTED;
            }
            break;
            default:
                break;
            }
        }

        return error;
    }

    virtual DWORD Free()
    {
        DWORD error = ERROR_SUCCESS;

        if (_pointer != nullptr)
        {
            switch (_allocType)
            {
            case AllocType::UseNewByteArray:
                delete[](byte*)(_pointer);
                break;
            case AllocType::UseHeapAlloc:
                if (!::HeapFree(GetProcessHeap(), 0, static_cast<LPVOID>(_pointer)))
                {
                    error = GetLastError();
                }
                break;
            case AllocType::UseLocalAlloc:
                if (::LocalFree(_pointer) != nullptr)
                {
                    error = GetLastError();
                }
                break;
            case AllocType::UseAllocateAndInitializeSid:
                if (::FreeSid(static_cast<PSID>(_pointer)) != nullptr)
                {
                    error = GetLastError();
                }
                break;
            default:
                break;
            }

            RETURN_IF_FAILED(error);
            _pointer = nullptr;
            _allocType = AllocType::None;
        }

        return error;
    }
};

class Sid : public Pointer<VOID>
{
private:
    std::wstring _str;
    WELL_KNOWN_SID_TYPE _type;
    std::wstring _strType;
    bool _typeChecked;
    bool _isWellKnown;

    void CheckWellKnownSidType()
    {
        if (!_typeChecked)
        {
            _isWellKnown = GetWellKnownSidType(_pointer, _type, _strType);
            _typeChecked = true;
        }
    }

public:

    Sid(PSID sid = nullptr, AllocType allocType = AllocType::None)
        : Pointer(sid, allocType), _type(WinNullSid), _typeChecked(false), _isWellKnown(false)
    {}

    std::wstring& Str()
    {
        DWORD error = ERROR_SUCCESS;

        if (_str.empty())
        {
            Pointer<WCHAR> str;
            if (!::ConvertSidToStringSidW(_pointer, &str.Get()))
            {
                error = GetLastError();
                std::wcerr << L"ConvertSidToStringSidW(0x" << std::hex << _pointer << std::dec << L") failed, error=" << error << std::endl;
            }
            else
            {
                str.SetAllocType(AllocType::UseLocalAlloc);
                _str.assign(str.Get());
            }
        }

        return _str;
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

    std::wstring& WellKnownSidTypeString()
    {
        CheckWellKnownSidType();
        return _strType;
    }

    virtual DWORD Free() override
    {
        _str.clear();
        _type = WinNullSid;
        _strType.clear();
        _typeChecked = false;
        _isWellKnown = false;
        return Pointer::Free();
    }

    std::wstring Description()
    {
        std::wostringstream oss;
        oss << Str() << L"[IsWellKnown=" << IsWellKnown();

        if (_isWellKnown)
        {
            oss << L"|Type=" << _type << L"|" << _strType;
        }

        oss << L"]";
        return oss.str();
    }

    void Print()
    {
        std::wcout << Description() << std::endl;
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

    HANDLE Release()
    {
        HANDLE copy = _handle;
        _handle = INVALID_HANDLE_VALUE;
        return copy;
    }

    void Attach(HANDLE handle)
    {
        if (_handle != INVALID_HANDLE_VALUE)
        {
            Close();
        }

        _handle = handle;
    }

    Handle& operator=(HANDLE handle)
    {
        Attach(handle);
        return *this;
    }

    bool operator==(HANDLE handle)
    {
        return _handle == handle;
    }

    DWORD Close()
    {
        DWORD error = ERROR_SUCCESS;

        if (_handle == INVALID_HANDLE_VALUE)
        {
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

class Token : public Handle
{
private:
    bool _isThreadToken;
    std::wstring _type;
    Pointer<TOKEN_USER> _user;
    Pointer<TOKEN_GROUPS> _groups;
    Pointer<TOKEN_OWNER> _owner;
    Pointer<TOKEN_PRIMARY_GROUP> _primaryGroup;
    Pointer<TOKEN_PRIVILEGES> _privileges;

public:

    Token(HANDLE tokenHandle = INVALID_HANDLE_VALUE, bool isThreadToken = false)
        : Handle(tokenHandle),
        _isThreadToken(isThreadToken)
    {
        _type = _isThreadToken ? L"thread" : L"process";
    }

    DWORD Open()
    {
        DWORD error = ERROR_SUCCESS;
        BOOL success;

        if (_handle == INVALID_HANDLE_VALUE)
        {
            if (_isThreadToken)
            {
                success = OpenThreadToken(
                    GetCurrentThread(),
                    TOKEN_ALL_ACCESS,
                    TRUE,
                    &_handle);
            }
            else
            {
                success = OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_ALL_ACCESS,
                    &_handle);
            }

            if (success)
            {
                std::wcout << L"Opened " << _type << L" token 0x" << std::hex << _handle << std::dec << std::endl;
            }
            else
            {
                error = GetLastError();
                std::wcerr << L"Failed to open " << _type << L" token." << std::endl;
            }
        }
        else
        {
            std::wcout << L"Already opened " << _type << L" token 0x" << std::hex << _handle << std::dec << std::endl;
        }

        return error;
    }

    DWORD Duplicate(
        PHANDLE duplicateTokenHandle,
        SECURITY_IMPERSONATION_LEVEL impersonationLevel = SECURITY_IMPERSONATION_LEVEL::SecurityImpersonation,
        TOKEN_TYPE tokenType = TOKEN_TYPE::TokenImpersonation)
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
            TOKEN_ALL_ACCESS,
            NULL,
            impersonationLevel,
            tokenType,
            duplicateTokenHandle))
        {
            error = GetLastError();
            RETURN_FAILURE(error);
        }

        return error;
    }

    template<typename TokenInfo>
    DWORD GetTokenInformation(TOKEN_INFORMATION_CLASS tokenClass, Pointer<TokenInfo>& tokenInfo, bool refresh = false)
    {
        DWORD error = ERROR_SUCCESS;
        std::unique_ptr<byte[]> buffer;

        if (tokenInfo != nullptr && refresh)
        {
            tokenInfo.Free();
        }

        if (tokenInfo == nullptr)
        {
            error = Open();
            RETURN_IF_FAILED(error);

            if (error == ERROR_SUCCESS)
            {
                error = ::GetTokenInformation(_handle, tokenClass, buffer);
                RETURN_IF_FAILED(error);

                if (error == ERROR_SUCCESS)
                {
                    tokenInfo.Attach((TokenInfo*)buffer.get(), AllocType::UseNewByteArray);
                    buffer.release();
                }
            }
        }

        return error;
    }

    Pointer<TOKEN_USER>& User(bool refresh = false)
    {
        GetTokenInformation<TOKEN_USER>(TokenUser, _user, refresh);
        return _user;
    }

    Pointer<TOKEN_GROUPS>& Groups(bool refresh = false)
    {
        GetTokenInformation<TOKEN_GROUPS>(TokenGroups, _groups, refresh);
        return _groups;
    }

    Pointer<TOKEN_OWNER>& Owner(bool refresh = false)
    {
        GetTokenInformation<TOKEN_OWNER>(TokenOwner, _owner, refresh);
        return _owner;
    }

    Pointer<TOKEN_PRIMARY_GROUP>& PrimaryGroup(bool refresh = false)
    {
        GetTokenInformation<TOKEN_PRIMARY_GROUP>(TokenPrimaryGroup, _primaryGroup, refresh);
        return _primaryGroup;
    }

    Pointer<TOKEN_PRIVILEGES>& Privileges(bool refresh = false)
    {
        GetTokenInformation<TOKEN_PRIVILEGES>(TokenPrivileges, _privileges, refresh);
        return _privileges;
    }
};

class ThreadToken : public Token
{
public:
    ThreadToken() : Token(INVALID_HANDLE_VALUE, true) {}
};

class ProcessToken : public Token
{
public:
    ProcessToken() : Token(INVALID_HANDLE_VALUE, false) {}
};

DWORD ConcertSecurityDescriptorToString(PSECURITY_DESCRIPTOR securityDescriptor, std::wstring& securityDescriptorString)
{
    DWORD error = ERROR_SUCCESS;
    Pointer<WCHAR> str;
    ULONG strLen = 0;

    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
        securityDescriptor,
        SDDL_REVISION_1,
        SecurityDescriptorSecurityInformation,
        &str.Get(),
        &strLen))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (str == nullptr)
    {
        RETURN_FAILURE(ERROR_INVALID_SECURITY_DESCR);
    }

    str.SetAllocType(AllocType::UseLocalAlloc);
    securityDescriptorString.assign(str.Get());
    return error;
}

void PrintSecurityDescriptor(PSECURITY_DESCRIPTOR securityDescriptor)
{
    DWORD error = ERROR_SUCCESS;
    std::wstring securityDescriptorString;

    error = ConcertSecurityDescriptorToString(securityDescriptor, securityDescriptorString);

    if (error == ERROR_SUCCESS)
    {
        std::wcout << L"Security Descriptor: [" << securityDescriptorString << L"]" << std::endl;
    }
    else
    {
        std::wcerr << L"Failed to print security descriptor 0x" << std::hex << securityDescriptor << std::dec << L", error=" << error << std::endl;
    }
}

DWORD GetImpersonationToken(ThreadToken& impersonationToken)
{
    DWORD error = ERROR_SUCCESS;
    ProcessToken processToken;
    error = processToken.Open();
    RETURN_IF_FAILED(error);

    error = processToken.Duplicate(&impersonationToken.Get());
    return error;
}

DWORD PrintTokenPrivileges(Token& token)
{
    DWORD error = ERROR_SUCCESS;
    std::wcout << L"TokenPrivileges:" << std::endl;
    PrintPrivileges(*(token.Privileges().Get()));
    return error;
}

DWORD SetTokenPrivileges(HANDLE tokenHandle)
{
    DWORD error = ERROR_SUCCESS;

    error = SetTokenPrivilege(tokenHandle, SE_BACKUP_NAME, true);
    RETURN_IF_FAILED(error);

    error = SetTokenPrivilege(tokenHandle, SE_RESTORE_NAME, true);
    RETURN_IF_FAILED(error);

    error = SetTokenPrivilege(tokenHandle, SE_SECURITY_NAME, true);
    RETURN_IF_FAILED(error);

    // Security Settings, Local Policies, User Rights Assignment, Create a token object
    // error = SetTokenPrivilege(tokenHandle, SE_CREATE_TOKEN_NAME, true);
    // RETURN_IF_FAILED(error);

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

DWORD CreateWellKnownSid(WELL_KNOWN_SID_TYPE type, Sid& sid, PSID domainSid = nullptr)
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> psid;
    DWORD size = 0;

    if (::CreateWellKnownSid(type, domainSid, nullptr, &size))
    {
        error = ERROR_BAD_ARGUMENTS;
        RETURN_FAILURE(error);
    }

    psid.reset(new byte[size]);

    if (!::CreateWellKnownSid(type, domainSid, psid.get(), &size))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    sid.Attach(static_cast<PSID>(psid.get()), AllocType::UseNewByteArray);
    psid.release();

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

typedef struct _SidAuthority {
    SID_IDENTIFIER_AUTHORITY authority;
    BYTE subAuthorityCount;
    DWORD subAuthority0;
    DWORD subAuthority1;
    DWORD subAuthority2;
    DWORD subAuthority3;
    DWORD subAuthority4;
    DWORD subAuthority5;
    DWORD subAuthority6;
    DWORD subAuthority7;

    _SidAuthority(
        const SID_IDENTIFIER_AUTHORITY& a = SECURITY_NT_AUTHORITY,
        BYTE saCount = 0,
        DWORD sa0 = 0,
        DWORD sa1 = 0,
        DWORD sa2 = 0,
        DWORD sa3 = 0,
        DWORD sa4 = 0,
        DWORD sa5 = 0,
        DWORD sa6 = 0,
        DWORD sa7 = 0)
        : authority(a),
        subAuthorityCount(saCount),
        subAuthority0(sa0),
        subAuthority1(sa1),
        subAuthority2(sa2),
        subAuthority3(sa3),
        subAuthority4(sa4),
        subAuthority5(sa5),
        subAuthority6(sa6),
        subAuthority7(sa7)
    {}

    void Parse(int argc, wchar_t* argv[])
    {
        int index = 0;
        subAuthorityCount = argc;

#define SET_SUB_AUTHORITY(x) \
    if (index < argc) \
    { \
        x = _wtoi(argv[index]); \
    } \
    index++;

        SET_SUB_AUTHORITY(subAuthority0);
        SET_SUB_AUTHORITY(subAuthority1);
        SET_SUB_AUTHORITY(subAuthority2);
        SET_SUB_AUTHORITY(subAuthority3);
        SET_SUB_AUTHORITY(subAuthority4);
        SET_SUB_AUTHORITY(subAuthority5);
        SET_SUB_AUTHORITY(subAuthority6);
        SET_SUB_AUTHORITY(subAuthority7);

#undef SET_SUB_AUTHORITY
    }
} SidAuthority, *PSidAuthority;

DWORD CreateSid(Sid& sid, const SidAuthority& sidAuthority)
{
    DWORD error = ERROR_SUCCESS;
    PSID psid = nullptr;

    if (!::AllocateAndInitializeSid(
        const_cast<PSID_IDENTIFIER_AUTHORITY>(&sidAuthority.authority),
        sidAuthority.subAuthorityCount,
        sidAuthority.subAuthority0,
        sidAuthority.subAuthority1,
        sidAuthority.subAuthority2,
        sidAuthority.subAuthority3,
        sidAuthority.subAuthority4,
        sidAuthority.subAuthority5,
        sidAuthority.subAuthority6,
        sidAuthority.subAuthority7,
        &psid))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    sid.Attach(psid, AllocType::UseAllocateAndInitializeSid);
    return error;
}

DWORD CreateRandomSid(Sid& sid, SidAuthority& sidAuthority)
{
    DWORD error = ERROR_SUCCESS;
    BYTE count = 0;
    const BYTE maxCount = 8;

    if (sidAuthority.subAuthorityCount == 0)
    {
        sidAuthority.subAuthorityCount = rand() % maxCount;
    }

#define SET_SUB_AUTHORITY(x) \
    if (count++ < sidAuthority.subAuthorityCount) \
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

    SET_SUB_AUTHORITY(sidAuthority.subAuthority0);
    SET_SUB_AUTHORITY(sidAuthority.subAuthority1);
    SET_SUB_AUTHORITY(sidAuthority.subAuthority2);
    SET_SUB_AUTHORITY(sidAuthority.subAuthority3);
    SET_SUB_AUTHORITY(sidAuthority.subAuthority4);
    SET_SUB_AUTHORITY(sidAuthority.subAuthority5);
    SET_SUB_AUTHORITY(sidAuthority.subAuthority6);
    SET_SUB_AUTHORITY(sidAuthority.subAuthority7);

#undef SET_SUB_AUTHORITY

    error = CreateSid(sid, sidAuthority);
    RETURN_IF_FAILED(error);
    return error;
}

DWORD PrintCreateSid(const SidAuthority& sidAuthority)
{
    DWORD error = ERROR_SUCCESS;
    Sid sid;

    error = CreateSid(sid, sidAuthority);
    RETURN_IF_FAILED(error);

    sid.Print();
    return error;
}

DWORD PrintCreateRandomSid(SidAuthority& sidAuthority)
{
    DWORD error = ERROR_SUCCESS;
    Sid sid;

    error = CreateRandomSid(sid, sidAuthority);
    RETURN_IF_FAILED(error);

    sid.Print();
    return error;
}


DWORD PrintSids()
{
    DWORD error = ERROR_SUCCESS;

    PrintCreateSid({ SECURITY_NULL_SID_AUTHORITY, 1, SECURITY_NULL_RID });
    PrintCreateSid({ SECURITY_WORLD_SID_AUTHORITY, 1, SECURITY_NULL_RID });
    PrintCreateSid({ SECURITY_LOCAL_SID_AUTHORITY, 1, SECURITY_NULL_RID });
    PrintCreateSid({ SECURITY_CREATOR_SID_AUTHORITY, 1, SECURITY_NULL_RID });
    PrintCreateSid({ SECURITY_NON_UNIQUE_AUTHORITY, 1, SECURITY_NULL_RID });
    PrintCreateSid({ SECURITY_RESOURCE_MANAGER_AUTHORITY, 1, SECURITY_NULL_RID });

    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 1, 1 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 1 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 2, 1, 2 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 2 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 3, 1, 2, 3 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 3 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 4, 1, 2, 3, 4 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 4 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 5, 1, 2, 3, 4, 5 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 5 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 6, 1, 2, 3, 4, 5, 6 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 6 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 7, 1, 2, 3, 4, 5, 6, 7 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 7 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
        PrintCreateRandomSid(sa);
    }
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY, 8 };
        PrintCreateRandomSid(sa);
    }

    for (int i = 0; i < 20; i++)
    {
        SidAuthority sa = { SECURITY_NT_AUTHORITY };
        PrintCreateRandomSid(sa);
    }

    return error;
}

DWORD PrintSid(int argc, wchar_t* argv[])
{
    DWORD error = ERROR_SUCCESS;
    std::unique_ptr<byte[]> psid;
    Sid sid;
    SidAuthority sa;

    sa.Parse(argc, argv);

    error = CreateSid(
        psid,
        sa.authority,
        sa.subAuthorityCount,
        sa.subAuthority0,
        sa.subAuthority1,
        sa.subAuthority2,
        sa.subAuthority3,
        sa.subAuthority4,
        sa.subAuthority5,
        sa.subAuthority6,
        sa.subAuthority7);
    RETURN_IF_FAILED(error);

    sid.Attach(static_cast<PSID>(psid.get()));
    sid.Print();
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
            error = ::GetExplicitEntriesFromAclW(_acl, &_acesCount, &_aces);

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

DWORD AceString(const EXPLICIT_ACCESS_W& ace, std::wstring& aceStr)
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
    PSID* owner,
    LPBOOL ownerDefaulted,
    PSID* group,
    LPBOOL groupDefaulted,
    PACL* dacl,
    LPBOOL daclPresent,
    LPBOOL daclDefaulted,
    PACL* sacl,
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
        std::wstring strSecurityDescriptor;

        if (_pSecurityDescriptor == NULL)
        {
            return strSecurityDescriptor;
        }

        error = ConcertSecurityDescriptorToString(_pSecurityDescriptor, strSecurityDescriptor);

        if (error != ERROR_SUCCESS)
        {
            std::wcerr << L"Failed to convert security descriptor 0x" << std::hex << _pSecurityDescriptor << std::dec << L" to string, error=" << error << std::endl;
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
        GENERIC_READ | ACCESS_SYSTEM_SECURITY | WRITE_OWNER | WRITE_DAC | READ_CONTROL,
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

DWORD PrintSid(const PSID psid)
{
    DWORD error = ERROR_SUCCESS;
    Sid sid;
    sid.Attach(psid);
    sid.Print();
    return error;
}

DWORD PrintSidAndAttributes(const SID_AND_ATTRIBUTES& sa)
{
    DWORD error = ERROR_SUCCESS;
    Sid sid;
    sid.Attach(sa.Sid);
    std::wcout << sid.Description();

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

DWORD PrintTokenGroups(const PTOKEN_GROUPS groups)
{
    DWORD error = ERROR_SUCCESS;

    for (DWORD i = 0; i < groups->GroupCount; i++)
    {
        std::wcout << L"Group[" << i << L"]: ";
        PrintSidAndAttributes(groups->Groups[i]);
    }

    return error;
}

DWORD SetTokenUser(HANDLE tokenHandle, const PSID sid)
{
    DWORD error = ERROR_SUCCESS;
    TOKEN_USER user;

    user.User.Sid = sid;
    user.User.Attributes = 0;

    if (!SetTokenInformation(
        tokenHandle,
        TOKEN_INFORMATION_CLASS::TokenUser,
        &user,
        sizeof(user) + GetLengthSid(user.User.Sid)))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    return error;
}

DWORD SetTokenUser(HANDLE tokenHandle, int argc, wchar_t* argv[])
{
    DWORD error = ERROR_SUCCESS;

    if (argc <= 0)
    {
        RETURN_FAILURE(ERROR_BAD_ARGUMENTS);
    }

    if (argv[0][0] == L'S')
    {
        PSID psid = nullptr;
        Sid sid;

        if (!ConvertStringSidToSidW(argv[0], &psid))
        {
            error = GetLastError();
            RETURN_FAILURE(error);
        }

        sid.Attach(psid, AllocType::UseLocalAlloc);

        error = SetTokenUser(tokenHandle, psid);
    }
    else
    {
        std::unique_ptr<byte[]> psid;
        SidAuthority sa;
        sa.Parse(argc, argv);

        error = CreateSid(
            psid,
            sa.authority,
            sa.subAuthorityCount,
            sa.subAuthority0,
            sa.subAuthority1,
            sa.subAuthority2,
            sa.subAuthority3,
            sa.subAuthority4,
            sa.subAuthority5,
            sa.subAuthority6,
            sa.subAuthority7);
        RETURN_IF_FAILED(error);

        error = SetTokenUser(tokenHandle, static_cast<PSID>(psid.get()));
    }
    return error;
}

DWORD PrintTokenInformation(Token& token)
{
    std::wcout << L"Token user =======>" << std::endl;
    PrintSidAndAttributes(token.User()->User);
    std::wcout << L"Token groups =======>" << std::endl;
    PrintTokenGroups(token.Groups().Get());
    std::wcout << L"Token owner =======>" << std::endl;
    PrintSid(token.Owner()->Owner);
    std::wcout << L"Token primary group =======>" << std::endl;
    PrintSid(token.PrimaryGroup()->PrimaryGroup);
    std::wcout << L"Token privileges =======>" << std::endl;
    PrintTokenPrivileges(token);
    return ERROR_SUCCESS;
}

class Arg
{
private:
    wchar_t** _argv;
    int _argc;
    int _index;

public:
    Arg(int argc, wchar_t* argv[], int index = 0)
        : _argc(argc), _argv(argv), _index(index)
    {}

    bool HasNext() const
    {
        return _index < _argc;
    }

    wchar_t* Next()
    {
        return HasNext() ? _argv[_index++] : nullptr;
    }

    std::wstring NextAsString()
    {
        return HasNext() ? std::wstring(_argv[_index++]) : L"";
    }

    int RemainingArgCount() const
    {
        return _argc - _index;
    }

    wchar_t** RemainingArgs() const
    {
        return &_argv[_index];
    }

    Arg Remaining()
    {
        return Arg(_argc - _index, &_argv[_index], 0);
    }
};

DWORD ProcessTokenMain(Arg& arg)
{
    DWORD error = ERROR_SUCCESS;
    ProcessToken processToken;

    error = processToken.Open();
    RETURN_IF_FAILED(error);

    if (arg.HasNext())
    {
        std::wstring command = arg.NextAsString();

        if (command == L"duplicate")
        {
            ThreadToken duplicateToken;

            std::wcout << L"Duplicate process token =======>" << std::endl;
            error = processToken.Duplicate(&duplicateToken.Get());
            RETURN_IF_FAILED(error);

            error = PrintTokenInformation(duplicateToken);
        }
        else
        {
            error = ERROR_BAD_ARGUMENTS;
        }
    }
    else
    {
        error = PrintTokenInformation(processToken);
    }

    return error;
}

DWORD ThreadTokenMain(Arg& arg)
{
    DWORD error = ERROR_SUCCESS;

    Impersonator impersonator;
    error = impersonator.BeginImpersonateSelf();
    RETURN_IF_FAILED(error);

    ThreadToken threadToken;
    error = threadToken.Open();
    RETURN_IF_FAILED(error);

    if (arg.HasNext())
    {
        int argIndex = 0;
        std::wstring command(arg.Next());

        if (command == L"duplicate")
        {
            ThreadToken duplicateToken;

            std::wcout << L"Duplicate thread token =======>" << std::endl;
            error = threadToken.Duplicate(&duplicateToken.Get());
            RETURN_IF_FAILED(error);

            error = PrintTokenInformation(duplicateToken);

        }
        else if (command == L"user")
        {
            if (!arg.HasNext())
            {
                RETURN_FAILURE(ERROR_BAD_ARGUMENTS);
            }

            ThreadToken duplicateToken;

            std::wcout << L"Duplicate thread token =======>" << std::endl;
            error = threadToken.Duplicate(&duplicateToken.Get());
            RETURN_IF_FAILED(error);

            error = SetTokenUser(duplicateToken.Get(), arg.RemainingArgCount(), arg.RemainingArgs());
            RETURN_IF_FAILED(error);

            std::wcout << L"Duplicate token user =======>" << std::endl;
            PrintSidAndAttributes(duplicateToken.User(true)->User);
        }
        else
        {
            RETURN_FAILURE(ERROR_BAD_ARGUMENTS);
        }
    }
    else
    {
        error = PrintTokenInformation(threadToken);
    }

    return error;
}

DWORD SecurityDescriptor1()
{
    DWORD error = ERROR_SUCCESS;
    ThreadToken impersonationToken;
    SECURITY_DESCRIPTOR sd;

    error = GetImpersonationToken(impersonationToken);
    RETURN_IF_FAILED(error);

    // Create a security descriptor without owner, group, dacl or sacl
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    PrintSecurityDescriptor(&sd);
    error = AccessCheck(&sd, impersonationToken.Get());
    return error;
}

DWORD SecurityDescriptor2()
{
    DWORD error = ERROR_SUCCESS;
    ThreadToken impersonationToken;
    SECURITY_DESCRIPTOR sd;

    error = GetImpersonationToken(impersonationToken);
    RETURN_IF_FAILED(error);

    // Create a security descriptor with a non-defaulted owner
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorOwner(
        &sd,
        impersonationToken.User()->User.Sid,
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    PrintSecurityDescriptor(&sd);
    error = AccessCheck(&sd, impersonationToken.Get());
    return error;
}

DWORD SecurityDescriptor3()
{
    DWORD error = ERROR_SUCCESS;
    ThreadToken impersonationToken;
    SECURITY_DESCRIPTOR sd;

    error = GetImpersonationToken(impersonationToken);
    RETURN_IF_FAILED(error);

    // Create a security descriptor with a defaulted owner
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorOwner(
        &sd,
        impersonationToken.User()->User.Sid,
        true))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    PrintSecurityDescriptor(&sd);
    error = AccessCheck(&sd, impersonationToken.Get());
    return error;
}

DWORD SecurityDescriptor4()
{
    DWORD error = ERROR_SUCCESS;
    ThreadToken impersonationToken;
    SECURITY_DESCRIPTOR sd;

    error = GetImpersonationToken(impersonationToken);
    RETURN_IF_FAILED(error);

    // Create a security descriptor with a non-defaulted group
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorGroup(
        &sd,
        impersonationToken.PrimaryGroup()->PrimaryGroup,
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    PrintSecurityDescriptor(&sd);
    error = AccessCheck(&sd, impersonationToken.Get());
    return error;
}

DWORD SecurityDescriptor5()
{
    DWORD error = ERROR_SUCCESS;
    ThreadToken impersonationToken;
    SECURITY_DESCRIPTOR sd;

    error = GetImpersonationToken(impersonationToken);
    RETURN_IF_FAILED(error);

    // Create a security descriptor with a defaulted group
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorGroup(
        &sd,
        impersonationToken.PrimaryGroup()->PrimaryGroup,
        true))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    PrintSecurityDescriptor(&sd);
    error = AccessCheck(&sd, impersonationToken.Get());
    return error;
}

DWORD SecurityDescriptor6()
{
    DWORD error = ERROR_SUCCESS;
    ThreadToken impersonationToken;
    SECURITY_DESCRIPTOR sd;

    error = GetImpersonationToken(impersonationToken);
    RETURN_IF_FAILED(error);

    // Create a security descriptor with a non-defaulted owner and a non-defaulted group
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorOwner(
        &sd,
        impersonationToken.User()->User.Sid,
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorGroup(
        &sd,
        impersonationToken.PrimaryGroup()->PrimaryGroup,
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    PrintSecurityDescriptor(&sd);
    error = AccessCheck(&sd, impersonationToken.Get());
    return error;
}

DWORD SecurityDescriptor7()
{
    DWORD error = ERROR_SUCCESS;
    ThreadToken impersonationToken;
    SECURITY_DESCRIPTOR sd;
    Sid sid;

    error = GetImpersonationToken(impersonationToken);
    RETURN_IF_FAILED(error);

    // Create a security descriptor with a system owner and a system group
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    CreateWellKnownSid(WELL_KNOWN_SID_TYPE::WinLocalSystemSid, sid);

    if (!SetSecurityDescriptorOwner(
        &sd,
        sid.Get(),
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorGroup(
        &sd,
        sid.Get(),
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    PrintSecurityDescriptor(&sd);
    error = AccessCheck(&sd, impersonationToken.Get());
    return error;
}

DWORD SecurityDescriptor8()
{
    DWORD error = ERROR_SUCCESS;
    ThreadToken impersonationToken;
    SECURITY_DESCRIPTOR sd;
    Sid sid;

    error = GetImpersonationToken(impersonationToken);
    RETURN_IF_FAILED(error);

    // Create a security descriptor with an owner and a group
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    CreateSid(sid, { SECURITY_NT_AUTHORITY, 8, 1, 2, 3, 4, 5, 6, 7, 8 });

    if (!SetSecurityDescriptorOwner(
        &sd,
        sid.Get(),
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorGroup(
        &sd,
        sid.Get(),
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    PrintSecurityDescriptor(&sd);
    error = AccessCheck(&sd, impersonationToken.Get());
    return error;
}

DWORD SecurityDescriptor9()
{
    DWORD error = ERROR_SUCCESS;
    ThreadToken impersonationToken;
    SECURITY_DESCRIPTOR sd;
    Sid sid;

    error = GetImpersonationToken(impersonationToken);
    RETURN_IF_FAILED(error);

    // Create a security descriptor with an owner and a group and no dacl
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    CreateSid(sid, { SECURITY_NT_AUTHORITY, 8, 1, 2, 3, 4, 5, 6, 7, 8 });

    if (!SetSecurityDescriptorOwner(
        &sd,
        sid.Get(),
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorGroup(
        &sd,
        sid.Get(),
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorDacl(
        &sd,
        false,
        nullptr,
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    PrintSecurityDescriptor(&sd);
    error = AccessCheck(&sd, impersonationToken.Get());
    return error;
}

DWORD SecurityDescriptor10()
{
    DWORD error = ERROR_SUCCESS;
    ThreadToken impersonationToken;
    SECURITY_DESCRIPTOR sd;
    Sid sid;

    error = GetImpersonationToken(impersonationToken);
    RETURN_IF_FAILED(error);

    // Create a security descriptor with an owner and a group and a null dacl
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    CreateSid(sid, { SECURITY_NT_AUTHORITY, 8, 1, 2, 3, 4, 5, 6, 7, 8 });

    if (!SetSecurityDescriptorOwner(
        &sd,
        sid.Get(),
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorGroup(
        &sd,
        sid.Get(),
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorDacl(
        &sd,
        true,
        nullptr,
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    PrintSecurityDescriptor(&sd);
    error = AccessCheck(&sd, impersonationToken.Get());
    return error;
}

DWORD SecurityDescriptor11()
{
    DWORD error = ERROR_SUCCESS;
    ThreadToken impersonationToken;
    SECURITY_DESCRIPTOR sd;
    ACL acl;
    Sid sid;

    error = GetImpersonationToken(impersonationToken);
    RETURN_IF_FAILED(error);

    // Create a security descriptor with an owner and a group and an empty dacl
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    CreateSid(sid, { SECURITY_NT_AUTHORITY, 8, 1, 2, 3, 4, 5, 6, 7, 8 });

    if (!SetSecurityDescriptorOwner(
        &sd,
        sid.Get(),
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorGroup(
        &sd,
        sid.Get(),
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!InitializeAcl(&acl, sizeof(acl), ACL_REVISION))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    if (!SetSecurityDescriptorDacl(
        &sd,
        true,
        &acl,
        false))
    {
        error = GetLastError();
        RETURN_FAILURE(error);
    }

    PrintSecurityDescriptor(&sd);
    error = AccessCheck(&sd, impersonationToken.Get());
    return error;
}

DWORD SecurityDescriptorMain(Arg& arg)
{
    DWORD error = ERROR_SUCCESS;

    if (arg.HasNext())
    {
        std::wstring securityDescriptorString = arg.NextAsString();
        std::wcout << L"Security descriptor is:\"" << securityDescriptorString << L"\"" << std::endl;

        SecurityDescriptor securityDescriptor;
        securityDescriptor.Set(securityDescriptorString);

        std::wcout << L"Dump:" << std::endl;
        securityDescriptor.Print();
    }
    else
    {
        SecurityDescriptor1();
        SecurityDescriptor2();
        SecurityDescriptor3();
        SecurityDescriptor4();
        SecurityDescriptor5();
        SecurityDescriptor6();
        SecurityDescriptor7();
        SecurityDescriptor8();
        SecurityDescriptor9();
        SecurityDescriptor10();
        SecurityDescriptor11();
    }

    return error;
}

DWORD SidMain(Arg& arg)
{
    DWORD error = ERROR_SUCCESS;

    if (!arg.HasNext())
    {
        error = PrintSids();
    }
    else
    {
        std::wstring command = arg.NextAsString();

        if (command == L"wellknown")
        {
            if (!arg.HasNext())
            {
                error = PrintWellKnownSids();
            }
            else
            {
                WELL_KNOWN_SID_TYPE type = static_cast<WELL_KNOWN_SID_TYPE>(_wtoi(arg.Next()));
                error = PrintWellKnownSid(type);
            }
        }
        else if (command == L"aai" || command == L"allocateandinitializesid")
        {
            error = PrintSids();
        }
        else if (command == L"create")
        {
            if (!arg.HasNext())
            {
                error = ERROR_BAD_ARGUMENTS;
            }
            else
            {
                error = PrintSid(arg.RemainingArgCount(), arg.RemainingArgs());
            }
        }
    }

    return error;
}

void Usage(int argc, wchar_t* argv[])
{
    std::wcout << L"Usage:" << std::endl;
    std::wcout << argv[0] << L" processtoken" << std::endl;
    std::wcout << argv[0] << L" processtoken duplicate" << std::endl;
    std::wcout << argv[0] << L" threadtoken" << std::endl;
    std::wcout << argv[0] << L" threadtoken duplicate" << std::endl;
    std::wcout << argv[0] << L" threadtoken user <subauthority0> <subauthority1> ..." << std::endl;
    std::wcout << argv[0] << L" threadtoken user <sid>" << std::endl;
    std::wcout << argv[0] << L" file <file path>" << std::endl;
    std::wcout << argv[0] << L" sd" << std::endl;
    std::wcout << argv[0] << L" sd <security descriptor>" << std::endl;
    std::wcout << argv[0] << L" sid" << std::endl;
    std::wcout << argv[0] << L" sid wellknown" << std::endl;
    std::wcout << argv[0] << L" sid wellknown <type>" << std::endl;
    std::wcout << argv[0] << L" sid aai|allocateandinitializesid" << std::endl;
    std::wcout << argv[0] << L" sid create <subauthority0> <subauthority1> ..." << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
    DWORD error = ERROR_SUCCESS;
    Arg arg(argc, argv, 1);

    if (!arg.HasNext())
    {
        Usage(argc, argv);
        return ERROR_BAD_ARGUMENTS;
    }

    std::wstring command = arg.NextAsString();

    if (command == L"processtoken")
    {
        error = ProcessTokenMain(arg);
    }
    else if (command == L"threadtoken")
    {
        error = ThreadTokenMain(arg);
    }
    else if (command == L"file")
    {
        if (!arg.HasNext())
        {
            Usage(argc, argv);
            return ERROR_BAD_ARGUMENTS;
        }

        Impersonator impersonator;
        error = impersonator.BeginImpersonateSelf();
        RETURN_IF_FAILED(error);

        error = SetThreadTokenPrivileges();
        RETURN_IF_FAILED(error);

        error = PrintFileSecurityDescriptor(arg.NextAsString());
    }
    else if (command == L"sd")
    {
        error = SecurityDescriptorMain(arg);
    }
    else if (command == L"sid")
    {
        error = SidMain(arg);
    }
    else
    {
        Usage(argc, argv);
        error = ERROR_BAD_ARGUMENTS;
    }

    RETURN_IF_FAILED(error);
    return error;
}