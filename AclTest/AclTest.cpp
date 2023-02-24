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

class Handle
{
private:
    HANDLE _handle;

public:
    Handle(HANDLE handle) : _handle(handle) {}
    Handle() : Handle(INVALID_HANDLE_VALUE) {}

    ~Handle()
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

DWORD SetPrivileges()
{
    DWORD error = ERROR_SUCCESS;
    ThreadToken token;

    error = token.Open();
    RETURN_IF_FAILED(error);

    error = SetPrivilege(token.Handle(), SE_BACKUP_NAME, true);
    RETURN_IF_FAILED(error);

    error = SetPrivilege(token.Handle(), SE_RESTORE_NAME, true);
    RETURN_IF_FAILED(error);
        
    error = SetPrivilege(token.Handle(), SE_SECURITY_NAME, true);
    RETURN_IF_FAILED(error);
        
    // PrintTokenPrivileges(token.Handle());

    return error;
}

class Sid
{
private:
    PSID _sid;
    LPWSTR _str;

public:
    Sid(PSID sid) : _sid(sid), _str(NULL) {}

    ~Sid()
    {
        Free();
    }

    std::wstring Str()
    {
        DWORD error = ERROR_SUCCESS;

        if (_str == NULL)
        {
            if (!ConvertSidToStringSidW(_sid, &_str))
            {
                error = GetLastError();
                std::wcerr << L"ConvertSidToStringSidW(0x" << std::hex << _sid << std::dec << L") failed, error=" << error << std::endl;
            }
        }

        return std::wstring(_str);
    }

    DWORD Free()
    {
        DWORD error = ERROR_SUCCESS;

        if (_str != NULL)
        {
            if (LocalFree(_str) != NULL)
            {
                error = GetLastError();
                RETURN_FAILURE(error);
            }

            _str = NULL;
        }

        return error;
    }
};

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

    oss << L"][Mode:" << ace.grfAccessMode;

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

    oss << L"][Inheritance:0x" << std::hex << ace.grfInheritance << std::dec;

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

    oss << L"][Trustee:";
    oss << L"[pMultipleTrustee:0x" << std::hex << ace.Trustee.pMultipleTrustee << std::dec << L"] ";
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
    oss << L"][TrusteeForm:" << ace.Trustee.TrusteeForm << L"|";
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
    oss << L"][TrusteeType:" << ace.Trustee.TrusteeType << L"|";
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
    oss << L"][";
    switch (ace.Trustee.TrusteeForm)
    {
    case TRUSTEE_IS_SID:
        {
            Sid sid(static_cast<PSID>(ace.Trustee.ptstrName));
            oss << L"SID:" << sid.Str();
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
            oss << L"[Sid:" << sid.Str() << L"]";
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

        }
        oss << L"TRUSTEE_IS_OBJECTS_AND_NAME";
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

class SecurityDescriptor
{
private:
    PSECURITY_DESCRIPTOR _pSecurityDescriptor;
    PSID _pOwner;
    PSID _pGroup;
    PACL _pDacl;
    PACL _pSacl;

public:
    SecurityDescriptor()
        : _pSecurityDescriptor(NULL), _pOwner(NULL), _pGroup(NULL), _pDacl(NULL), _pSacl(NULL)
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

    DWORD Free()
    {
        DWORD error = ERROR_SUCCESS;

        if (_pSecurityDescriptor != NULL)
        {
            if (LocalFree(_pSecurityDescriptor) != NULL)
            {
                error = GetLastError();
                std::wcerr << L"Failed to free security descriptor 0x" << std::hex << _pSecurityDescriptor << std::dec << std::endl;
                return error;
            }

            std::wcout << L"Freed security descriptor 0x" << std::hex << _pSecurityDescriptor << std::dec << std::endl;

            _pSecurityDescriptor = NULL;
            _pOwner = NULL;
            _pGroup = NULL;
            _pDacl = NULL;
            _pSacl = NULL;
        }

        return error;
    }

    DWORD Print()
    {
        DWORD error = ERROR_SUCCESS;
        DWORD length = 0;
        DWORD revision = 0;
        SECURITY_DESCRIPTOR_CONTROL control = { 0 };
        PSID owner = NULL;
        BOOL ownerDefaulted = FALSE;
        PSID group = NULL;
        BOOL groupDefaulted = FALSE;
        PACL dacl = NULL;
        BOOL daclPresent = FALSE;
        BOOL daclDefaulted = FALSE;
        PACL sacl = NULL;
        BOOL saclPresent = FALSE;
        BOOL saclDefaulted = FALSE;
        PBYTE pb;
        PWORD pw;

        if (_pSecurityDescriptor == NULL)
        {
            return error;
        }

        if (IsValidSecurityDescriptor(_pSecurityDescriptor))
        {
            length = GetSecurityDescriptorLength(_pSecurityDescriptor);
        }

        if (!GetSecurityDescriptorControl(
            _pSecurityDescriptor,
            &control,
            &revision))
        {
            error = GetLastError();
            RETURN_FAILURE(error);
        }

        if (!GetSecurityDescriptorOwner(
            _pSecurityDescriptor,
            &owner,
            &ownerDefaulted))
        {
            error = GetLastError();
            RETURN_FAILURE(error);
        }

        if (!GetSecurityDescriptorGroup(
            _pSecurityDescriptor,
            &group,
            &groupDefaulted))
        {
            error = GetLastError();
            RETURN_FAILURE(error);
        }

        if (!GetSecurityDescriptorDacl(
            _pSecurityDescriptor,
            &daclPresent,
            &dacl,
            &daclDefaulted))
        {
            error = GetLastError();
            RETURN_FAILURE(error);
        }

        if (!GetSecurityDescriptorSacl(
            _pSecurityDescriptor,
            &saclPresent,
            &sacl,
            &saclDefaulted))
        {
            error = GetLastError();
            RETURN_FAILURE(error);
        }

        pb = (PBYTE)_pSecurityDescriptor;
        std::wcout << L"SecurityDescriptor 0x" << std::hex << pb << std::dec << std::endl;
        std::wcout << L"  Length: " << length << std::endl;
        std::wcout << L"  Revision: " << revision << L"[" << pb[0] << L"]" << std::endl;
        std::wcout << L"  Sbz1: " << pb[1] << std::endl;
        pw = (PWORD)(pb + 2);
        std::wcout << L"  Control: 0x" << std::hex << control << L"[" << *pw << L"]" << std::dec;

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

        std::wcout << L"  Owner: 0x" << std::hex << owner << L"[" << _pOwner << L"]" << std::dec;
        Sid ownerSid(owner);
        std::wcout << ownerSid.Str() << std::endl;

        if (owner != NULL)
        {
            std::wcout << L"  OwnerDefaulted: " << ownerDefaulted << std::endl;
        }

        std::wcout << L"  Group: 0x" << std::hex << group << L"[" << _pGroup << L"]" << std::dec;
        Sid groupSid(group);
        std::wcout << groupSid.Str() << std::endl;

        if (group != NULL)
        {
            std::wcout << L"  GroupDefaulted: " << groupDefaulted << std::endl;
        }

        if (daclPresent)
        {
            std::wcout << L" Dacl: 0x" << std::hex << dacl << L"[" << _pDacl << L"]" << std::dec << std::endl;
            std::wcout << L" DaclDefaulted: " << daclDefaulted << std::endl;
            Acl daclObj(dacl);
            ULONG acesCount = daclObj.AcesCount();
            std::wcout << L"  Dacl ACEs Count: " << acesCount << std::endl;
            PEXPLICIT_ACCESS_W aces = daclObj.Aces();
            for (ULONG i = 0; i < acesCount; i++)
            {
                std::wstring aceStr;
                AceString(aces[i], aceStr);
                std::wcout << L"  Dacl ACE[" << i << L"]:" << aceStr << std::endl;
            }
        }

        if (saclPresent)
        {
            std::wcout << L" Sacl: 0x" << std::hex << sacl << L"[" << _pSacl << L"]" << std::dec << std::endl;
            std::wcout << L" SaclDefaulted: " << saclDefaulted << std::endl;
            Acl saclObj(sacl);
            std::wcout << L"  Sacl ACEs Count: " << saclObj.AcesCount() << std::endl;
            std::wcout << L"  Sacl ACEs: 0x" << std::hex << saclObj.Aces() << std::dec << std::endl;
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
        | SCOPE_SECURITY_INFORMATION
        | BACKUP_SECURITY_INFORMATION;

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

int wmain(int argc, wchar_t* argv[])
{
    DWORD error = ERROR_SUCCESS;

    Impersonator impersonator;
    error = impersonator.BeginImpersonateSelf();
    RETURN_IF_FAILED(error);

    error = SetPrivileges();
    RETURN_IF_FAILED(error);

    if (argc > 1)
    {
        error = PrintFileSecurityDescriptor(argv[1]);
        RETURN_IF_FAILED(error);
    }

    return error;
}