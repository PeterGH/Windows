#include <Windows.h>
#include <AclAPI.h>
#include <sddl.h>
#include <iostream>
#include <sstream>
#include <string>

DWORD LocalFreeIf(HLOCAL buffer)
{
    DWORD error = ERROR_SUCCESS;

    if (buffer != nullptr)
    {
        if (::LocalFree(buffer) != NULL)
        {
            error = ::GetLastError();
            std::wcerr << L"LocalFree(0x" << std::hex << buffer << std::dec << L" failed with error " << error << std::endl;
        }
    }

    return error;
}

DWORD CloseHandleIf(HANDLE handle)
{
    DWORD error = ERROR_SUCCESS;

    if (handle != INVALID_HANDLE_VALUE)
    {
        if (!::CloseHandle(handle))
        {
            error = ::GetLastError();
            std::wcerr << L"CloseHandle(0x" << std::hex << handle << std::dec << L" failed with error " << error << std::endl;
        }
    }

    return error;
}

DWORD EnablePrivilege(LUID_AND_ATTRIBUTES& privilege, LPCWSTR privilegeName)
{
    DWORD error = ERROR_SUCCESS;
    LUID luid{ 0 };

    if (::LookupPrivilegeValueW(nullptr, privilegeName, &luid))
    {
        // std::wcout << L"LUID(" << privilegeName << L") is 0x" << std::hex << luid.HighPart << L":" << luid.LowPart << std::endl;
        privilege.Luid = luid;
        privilege.Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        error = GetLastError();
        std::wcerr << L"LookupPrivilegeValueW(" << privilegeName << ") failed with error " << error << std::endl;
    }

    return error;
}

DWORD SetThreadTokenPrivileges(HANDLE threadTokenHandle)
{
    DWORD error = ERROR_SUCCESS;
    LUID luid{ 0 };
    const DWORD PrivilegesSize = sizeof(DWORD) + 3 * sizeof(LUID_AND_ATTRIBUTES);
    byte privilegesBuffer[PrivilegesSize]{ 0 };
    PTOKEN_PRIVILEGES privileges = (PTOKEN_PRIVILEGES)privilegesBuffer;
    byte previousStateBuffer[PrivilegesSize]{ 0 };
    PTOKEN_PRIVILEGES previousState = (PTOKEN_PRIVILEGES)previousStateBuffer;
    DWORD previousStateSize = PrivilegesSize;

    if (threadTokenHandle == INVALID_HANDLE_VALUE)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    privileges->PrivilegeCount = 3;

    error = EnablePrivilege(privileges->Privileges[0], SE_BACKUP_NAME);
    if (error != ERROR_SUCCESS)
    {
        goto finally;
    }

    error = EnablePrivilege(privileges->Privileges[1], SE_RESTORE_NAME);
    if (error != ERROR_SUCCESS)
    {
        goto finally;
    }

    error = EnablePrivilege(privileges->Privileges[2], SE_SECURITY_NAME);
    if (error != ERROR_SUCCESS)
    {
        goto finally;
    }

    ::AdjustTokenPrivileges(
        threadTokenHandle,
        FALSE,
        privileges,
        previousStateSize,
        previousState,
        &previousStateSize);

    // AdjustTokenPrivileges returns success even when some privilegs are not set.
    // Must use GetLastError to check the result.
    error = GetLastError();
    if (error != ERROR_SUCCESS)
    {
        std::wcerr << L"AdjustTokenPrivileges failed with error " << error << std::endl;
    }

finally:

    return error;
}

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

DWORD ParseSecurityDescriptor(
    PSECURITY_DESCRIPTOR securityDescriptor,
    PDWORD revision,
    PDWORD sbz1,
    PSECURITY_DESCRIPTOR_CONTROL control,
    PSID* owner,
    PSID* group,
    PACL* sacl,
    PACL* dacl)
{
    if (securityDescriptor == nullptr || !::IsValidSecurityDescriptor(securityDescriptor))
    {
        return ERROR_INVALID_PARAMETER;
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_descriptor
    // however the parsed fields do not seem to be correct
    typedef struct {
        BYTE                        Revision;
        BYTE                        Sbz1;
        SECURITY_DESCRIPTOR_CONTROL Control;
        PSID                        Owner;
        PSID                        Group;
        PACL                        Sacl;
        PACL                        Dacl;
    } Local, *PLocal;

    PLocal local = (PLocal)securityDescriptor;
    *revision = local->Revision;
    *sbz1 = local->Sbz1;
    *control = local->Control;
    *owner = local->Owner;
    *group = local->Group;
    *sacl = local->Sacl;
    *dacl = local->Dacl;

    std::wcout << L"ParseSecurityDescriptor(0x" << std::hex << securityDescriptor << std::dec << L") returns:" << std::endl;
    std::wcout << L"  Revision: " << *revision << std::endl;
    std::wcout << L"  Sbz1: 0x" << *sbz1 << std::endl;
    std::wcout << L"  Control: 0x" << std::hex << *control << std::dec << std::endl;
    std::wcout << L"  POwner: 0x" << std::hex << *owner << std::dec << std::endl;
    std::wcout << L"  PGroup: 0x" << std::hex << *group << std::dec << std::endl;
    std::wcout << L"  PDacl: 0x" << std::hex << *dacl << std::dec << std::endl;
    std::wcout << L"  PSacl: 0x" << std::hex << *sacl << std::dec << std::endl;
    return ERROR_SUCCESS;
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

std::wstring GetSidNameUseString(SID_NAME_USE use)
{
#define RETURN_IF(u) \
    if (use == u) \
    { \
        return L#u; \
    }

    RETURN_IF(SidTypeUser);
    RETURN_IF(SidTypeGroup);
    RETURN_IF(SidTypeDomain);
    RETURN_IF(SidTypeAlias);
    RETURN_IF(SidTypeWellKnownGroup);
    RETURN_IF(SidTypeDeletedAccount);
    RETURN_IF(SidTypeInvalid);
    RETURN_IF(SidTypeUnknown);
    RETURN_IF(SidTypeComputer);
    RETURN_IF(SidTypeLabel);
    RETURN_IF(SidTypeLogonSession);

#undef RETURN_IF

    return L"";
}

DWORD GetSidDescription(PSID sid, BOOL defaulted, std::wstring& description)
{
    DWORD error = ERROR_SUCCESS;
    LPWSTR sidString = nullptr;
    WELL_KNOWN_SID_TYPE wellKnownSidType;
    std::wstring wellKnownSidTypeString;
    wchar_t accountName[256]{ 0 };
    DWORD accountNameSize = 256;
    wchar_t domainName[256]{ 0 };
    DWORD domainNameSize = 256;
    SID_NAME_USE use;
    std::wstring useString;
    std::wostringstream oss;

    if (!::ConvertSidToStringSidW(sid, &sidString))
    {
        error = ::GetLastError();
        std::wcerr << L"ConvertSidToStringSidW(0x" << std::hex << sid << std::dec << L" failed with error " << error << std::endl;
        goto finally;
    }

    if (!::LookupAccountSidW(
            nullptr,
            sid,
            accountName,
            &accountNameSize,
            domainName,
            &domainNameSize,
            &use))
    {
        error = ::GetLastError();
        std::wcerr << L"LookupAccountSidW(0x" << std::hex << sid << std::dec << L" failed with error " << error << std::endl;
        goto finally;
    }

    useString = GetSidNameUseString(use);

    oss << L"0x" << std::hex << sid << std::dec;

    if (defaulted)
    {
        oss << L"|Defaulted";
    }

    if (sidString != nullptr)
    {
        oss << L"|" << sidString;
    }

    if (GetWellKnownSidType(sid, wellKnownSidType, wellKnownSidTypeString))
    {
        oss << L"|" << wellKnownSidTypeString << L"(" << wellKnownSidType << L")";
    }

    oss << L"|" << domainName << L"\\" << accountName << L"|" << useString << L"(" << use << L")";

    description = oss.str();

finally:

    LocalFreeIf(sidString);

    return error;
}

DWORD GetAceDescription(PACE_HEADER header, std::wstring& description)
{
    DWORD error = ERROR_SUCCESS;
    std::wostringstream oss;

    if (header == nullptr)
    {
        error = ERROR_BAD_ARGUMENTS;
        goto finally;
    }

    oss << L"Type:" << header->AceType;
    oss << L"|Flags:" << header->AceFlags;
    oss << L"|Size:" << header->AceSize;

    description = oss.str();

finally:
    return error;
}

DWORD ProcessFile(const std::wstring& file)
{
    DWORD error = ERROR_SUCCESS;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
    LPWSTR securityDescriptorString = nullptr;
    ULONG securityDescriptorStringLength = 0;
    DWORD length = 0;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    PSID owner = nullptr;
    BOOL ownerDefaulted = FALSE;
    std::wstring ownerDescription;
    PSID group = nullptr;
    BOOL groupDefaulted = FALSE;
    std::wstring groupDescription;
    PACL dacl = nullptr;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    ACL_REVISION_INFORMATION daclRevision{ 0 };
    ACL_SIZE_INFORMATION daclSize{ 0 };
    PACL sacl = nullptr;
    BOOL saclPresent = FALSE;
    BOOL saclDefaulted = FALSE;
    PACE_HEADER ace = nullptr;
    std::wstring aceDescription;

    fileHandle = ::CreateFileW(
        file.c_str(),
        GENERIC_READ | ACCESS_SYSTEM_SECURITY | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        error = GetLastError();
        std::wcerr << L"CreateFileW(" << file << L") failed with error " << error << std::endl;
        goto finally;
    }

    std::wcout << file << std::endl;

    error = ::GetSecurityInfo(
        fileHandle,
        SE_FILE_OBJECT,
        SecurityDescriptorSecurityInformation,
        &owner,
        &group,
        &dacl,
        &sacl,
        &securityDescriptor);

    if (error != ERROR_SUCCESS)
    {
        std::wcerr << L"GetSecurityInfo(" << file << L") failed with error " << error << std::endl;
        goto finally;
    }

    // std::wcout << L"GetSecurityInfo(" << file << L") returns:" << std::endl;
    // std::wcout << L"  PSecurityDescriptor: 0x" << std::hex << securityDescriptor << std::dec << std::endl;
    // std::wcout << L"  POwner: 0x" << std::hex << owner << std::dec << std::endl;
    // std::wcout << L"  PGroup: 0x" << std::hex << group << std::dec << std::endl;
    // std::wcout << L"  PDacl: 0x" << std::hex << dacl << std::dec << std::endl;
    // std::wcout << L"  PSacl: 0x" << std::hex << sacl << std::dec << std::endl;

    // error = ParseSecurityDescriptor(
    //     securityDescriptor,
    //     &revision,
    //     &length,
    //     &control,
    //     &owner,
    //     &group,
    //     &sacl,
    //     &dacl);
    // if (error != ERROR_SUCCESS)
    // {
    //     std::wcerr << L"ParseSecurityDescriptor(" << file << L") failed with error " << error << std::endl;
    //     goto finally;
    // }

    if (!::ConvertSecurityDescriptorToStringSecurityDescriptorW(
            securityDescriptor,
            SDDL_REVISION_1,
            SecurityDescriptorSecurityInformation,
            &securityDescriptorString,
            &securityDescriptorStringLength))
    {
        error = ::GetLastError();
        std::wcerr << L"ConvertSecurityDescriptorToStringSecurityDescriptorW(0x" << std::hex << securityDescriptor << std::dec << L" failed with error " << error << std::endl;
        goto finally;
    }

    std::wcout << L"\"" << securityDescriptorString << L"\"" << std::endl;

    length = ::GetSecurityDescriptorLength(securityDescriptor);
    std::wcout << L"Length: " << length << std::endl;

    if (!::GetSecurityDescriptorControl(
            securityDescriptor,
            &control,
            &revision))
    {
        error = ::GetLastError();
        std::wcerr << L"GetSecurityDescriptorControl(0x" << std::hex << securityDescriptor << std::dec << L" failed with error " << error << std::endl;
        goto finally;
    }

    std::wcout << L"Revision: " << revision << std::endl;
    std::wcout << L"Control: 0x" << std::hex << control << std::dec;

#define OUT_CONTROL(x) \
        if (control & (x)) \
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

    if (!::GetSecurityDescriptorOwner(
            securityDescriptor,
            &owner,
            &ownerDefaulted))
    {
        error = ::GetLastError();
        std::wcerr << L"GetSecurityDescriptorOwner(0x" << std::hex << securityDescriptor << std::dec << L" failed with error " << error << std::endl;
        goto finally;
    }

    error = GetSidDescription(owner, ownerDefaulted, ownerDescription);
    if (error != ERROR_SUCCESS)
    {
        error = ::GetLastError();
        std::wcerr << L"GetSidDescription(0x" << std::hex << owner << std::dec << L" failed with error " << error << std::endl;
        goto finally;
    }

    std::wcout << L"POwner: " << ownerDescription << std::endl;

    if (!::GetSecurityDescriptorGroup(
            securityDescriptor,
            &group,
            &groupDefaulted))
    {
        error = ::GetLastError();
        std::wcerr << L"GetSecurityDescriptorGroup(0x" << std::hex << securityDescriptor << std::dec << L" failed with error " << error << std::endl;
        goto finally;
    }

    error = GetSidDescription(group, groupDefaulted, groupDescription);
    if (error != ERROR_SUCCESS)
    {
        error = ::GetLastError();
        std::wcerr << L"GetSidDescription(0x" << std::hex << group << std::dec << L" failed with error " << error << std::endl;
        goto finally;
    }

    std::wcout << L"PGroup: " << groupDescription << std::endl;

    if (!::GetSecurityDescriptorDacl(
            securityDescriptor,
            &daclPresent,
            &dacl,
            &daclDefaulted))
    {
        error = ::GetLastError();
        std::wcerr << L"GetSecurityDescriptorDacl(0x" << std::hex << securityDescriptor << std::dec << L" failed with error " << error << std::endl;
        goto finally;
    }

    std::wcout << L"PDacl: 0x" << std::hex << dacl << std::dec;

    if (daclPresent)
    {
        std::wcout << L"|Present";
    }

    if (daclDefaulted)
    {
        std::wcout << L"|Defaulted";
    }

    std::wcout << std::endl;

    if (dacl != nullptr)
    {

        if (!::GetAclInformation(dacl, &daclRevision, sizeof(ACL_REVISION_INFORMATION), AclRevisionInformation))
        {
            error = ::GetLastError();
            std::wcerr << L"GetAclInformation(0x" << std::hex << dacl << std::dec << L") failed with error " << error << std::endl;
            goto finally;
        }

        if (!::GetAclInformation(dacl, &daclSize, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation))
        {
            error = ::GetLastError();
            std::wcerr << L"GetAclInformation(0x" << std::hex << dacl << std::dec << L") failed with error " << error << std::endl;
            goto finally;
        }

        std::wcout << L"  AclRevision: " << dacl->AclRevision << L"|" << daclRevision.AclRevision << std::endl;
        std::wcout << L"  Sbz1: " << dacl->Sbz1 << std::endl;
        std::wcout << L"  AclSize: " << dacl->AclSize << L"|Free=" << daclSize.AclBytesFree << L"|InUse=" << daclSize.AclBytesInUse << std::endl;
        std::wcout << L"  AceCount: " << dacl->AceCount << L"|" << daclSize.AceCount << std::endl;
        std::wcout << L"  Sbz2: " << dacl->Sbz2 << std::endl;

        for (DWORD i = 0; i < daclSize.AceCount; i++)
        {
            if (!::GetAce(dacl, i, (LPVOID*)&ace))
            {
                error = ::GetLastError();
                std::wcerr << L"GetAce(0x" << std::hex << dacl << std::dec << L", " << i << L") failed with error " << error << std::endl;
                goto finally;
            }

            error = GetAceDescription(ace, aceDescription);
            if (error != ERROR_SUCCESS)
            {
                std::wcerr << L"GetAceDescription(0x" << std::hex << dacl << std::dec << L", " << i << L") failed with error " << error << std::endl;
                goto finally;
            }

            std::wcout << L"  ACE[" << i << L"]: " << aceDescription << std::endl;
        }
    }

    if (!::GetSecurityDescriptorSacl(
            securityDescriptor,
            &saclPresent,
            &sacl,
            &saclDefaulted))
    {
        error = ::GetLastError();
        std::wcerr << L"GetSecurityDescriptorSacl(0x" << std::hex << securityDescriptor << std::dec << L") failed with error " << error << std::endl;
        goto finally;
    }

    std::wcout << L"PSacl: 0x" << std::hex << sacl << std::dec;

    if (saclPresent)
    {
        std::wcout << L"|Present";
    }

    if (saclDefaulted)
    {
        std::wcout << L"|Defaulted";
    }

    std::wcout << std::endl;

    if (sacl != nullptr)
    {
        std::wcout << L"  AclRevision: " << sacl->AclRevision << std::endl;
        std::wcout << L"  Sbz1: " << sacl->Sbz1 << std::endl;
        std::wcout << L"  AclSize: " << sacl->AclSize << std::endl;
        std::wcout << L"  AceCount: " << sacl->AceCount << std::endl;
        std::wcout << L"  Sbz2: " << sacl->Sbz2 << std::endl;
    }

finally:

    LocalFreeIf(securityDescriptorString);
    LocalFreeIf(securityDescriptor);
    CloseHandleIf(fileHandle);

    return error;
}

void Usage(int argc, wchar_t* argv[])
{
    std::wcout << L"Usage:" << std::endl;
    std::wcout << argv[0] << L" <file path>" << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
    DWORD error = ERROR_SUCCESS;
    bool impersonating = false;
    HANDLE threadTokenHandle = INVALID_HANDLE_VALUE;

    if (argc < 2)
    {
        Usage(argc, argv);
        return ERROR_BAD_ARGUMENTS;
    }

    if (::ImpersonateSelf(SecurityImpersonation))
    {
        impersonating = true;
    }
    else
    {
        error = ::GetLastError();
        std::wcerr << L"ImpersonateSelf failed with error " << error << std::endl;
        goto finally;
    }

    if (!::OpenThreadToken(
            GetCurrentThread(),
            TOKEN_ALL_ACCESS,
            TRUE,
            &threadTokenHandle))
    {
        error = ::GetLastError();
        std::wcerr << L"OpenThreadToken failed with error " << error << std::endl;
        goto finally;
    }

    error = SetThreadTokenPrivileges(threadTokenHandle);
    if (error != ERROR_SUCCESS)
    {
        goto finally;
    }

    error = ProcessFile(argv[1]);

finally:

    CloseHandleIf(threadTokenHandle);

    if (impersonating)
    {
        if (!::RevertToSelf())
        {
            error = ::GetLastError();
            std::wcerr << L"RevertToSelf failed with error " << error << std::endl;
        }
    }

    return error;
}
