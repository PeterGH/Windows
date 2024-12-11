#define SECURITY_WIN32

#include <Windows.h>
#include <security.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#pragma comment(lib, "secur32.lib")

void PrintPackage(PSecPkgInfoW package)
{
    if (package == nullptr)
    {
        return;
    }

    std::wcout << package->Name << std::endl;
    std::wcout << L"\tVersion: " << package->wVersion << std::endl;
    std::wcout << L"\tRPCID:" << package->wRPCID << std::endl;
    std::wcout << L"\tMaxToken: " << package->cbMaxToken << std::endl;
    std::wcout << L"\tComment: " << package->Comment << std::endl;
    std::wcout << L"\tCapabilities: " << std::hex << package->fCapabilities << std::dec;

#define FLAG(x) \
if (package->fCapabilities & (x)) \
{ \
    std::wcout << L"|" << #x; \
}

    FLAG(SECPKG_FLAG_INTEGRITY);
    FLAG(SECPKG_FLAG_PRIVACY);
    FLAG(SECPKG_FLAG_TOKEN_ONLY);
    FLAG(SECPKG_FLAG_DATAGRAM);
    FLAG(SECPKG_FLAG_CONNECTION);
    FLAG(SECPKG_FLAG_MULTI_REQUIRED);
    FLAG(SECPKG_FLAG_CLIENT_ONLY);
    FLAG(SECPKG_FLAG_EXTENDED_ERROR);
    FLAG(SECPKG_FLAG_IMPERSONATION);
    FLAG(SECPKG_FLAG_ACCEPT_WIN32_NAME);
    FLAG(SECPKG_FLAG_STREAM);
    FLAG(SECPKG_FLAG_NEGOTIABLE);
    FLAG(SECPKG_FLAG_GSS_COMPATIBLE);
    FLAG(SECPKG_FLAG_LOGON);
    FLAG(SECPKG_FLAG_ASCII_BUFFERS);
    FLAG(SECPKG_FLAG_FRAGMENT);
    FLAG(SECPKG_FLAG_MUTUAL_AUTH);
    FLAG(SECPKG_FLAG_DELEGATION);
    FLAG(SECPKG_FLAG_READONLY_WITH_CHECKSUM);
    FLAG(SECPKG_FLAG_RESTRICTED_TOKENS);
    FLAG(SECPKG_FLAG_NEGO_EXTENDER);
    FLAG(SECPKG_FLAG_NEGOTIABLE2);
    FLAG(SECPKG_FLAG_APPCONTAINER_PASSTHROUGH);
    FLAG(SECPKG_FLAG_APPCONTAINER_CHECKS);
    FLAG(SECPKG_FLAG_CREDENTIAL_ISOLATION_ENABLED);
    FLAG(SECPKG_FLAG_APPLY_LOOPBACK);

#undef FLAG

    std::wcout << std::endl;
}

int EnumPackages()
{
    unsigned long cPackages = 0;
    PSecPkgInfoW pPackage = nullptr;

    SECURITY_STATUS status = EnumerateSecurityPackagesW(&cPackages, &pPackage);

    if (status == SEC_E_OK)
    {
        std::wcout << L"Found " << cPackages << L" packages." << std::endl;

        for (unsigned long i = 0; i < cPackages; i++)
        {
            std::wcout << L"Package " << i << L": ";
            PrintPackage(pPackage + i);
        }

        if (pPackage != nullptr)
        {
            status = FreeContextBuffer(pPackage);

            if (status == SEC_E_OK)
            {
                std::wcerr << L"Freed context buffer" << std::endl;
            }
            else
            {
                std::wcerr << L"Failed to free context buffer, error " << status << std::endl;
            }

            pPackage = nullptr;
        }
    }
    else
    {
        std::wcerr << L"Failed to enumerate security packages, error " << status << std::endl;
    }

    return status;
}

int TimeStampToUTCString(const TimeStamp& timestamp, std::wstring& utc) {
    DWORD error = NO_ERROR;
    FILETIME localFileTime{};

    localFileTime.dwLowDateTime = timestamp.LowPart;
    localFileTime.dwHighDateTime = timestamp.HighPart;

    SYSTEMTIME localSystemTime{};
    if (!FileTimeToSystemTime(&localFileTime, &localSystemTime))
    {
        error = GetLastError();
        return error;
    }

    SYSTEMTIME utcSystemTime{};
    if (!TzSpecificLocalTimeToSystemTime(nullptr, &localSystemTime, &utcSystemTime))
    {
        error = GetLastError();
        return error;
    }

    std::wostringstream oss;
    oss << std::setfill(L'0') << std::setw(4) << utcSystemTime.wYear << L"-"
        << std::setw(2) << utcSystemTime.wMonth << L"-"
        << std::setw(2) << utcSystemTime.wDay << L"T"
        << std::setw(2) << utcSystemTime.wHour << L":"
        << std::setw(2) << utcSystemTime.wMinute << L":"
        << std::setw(2) << utcSystemTime.wSecond << L"Z";

    utc = oss.str();

    return NO_ERROR;
}

std::wostream& operator<<(std::wostream& os, const SecHandle& handle)
{
    os << L"0x" << std::hex << handle.dwUpper << L":" << handle.dwLower << std::dec;
    return os;
}

class KerberosContext
{
protected:
    const std::wstring c_packageName{ L"Kerberos" };
    const ULONG c_targetDataRep{ SECURITY_NATIVE_DREP };

    std::wstring m_role;
    CredHandle m_credHandle{};
    CtxtHandle m_ctxtHandle{};
    ULONG m_contextReq{};
    ULONG m_contextAttr{};
    TimeStamp m_expiry{};
    bool m_firstCall{ true };

#define TRACEINFO std::wcout << L"[" << m_role << L"] "
#define TRACEERROR std::wcerr << L"[" << m_role << L"] "
#define TRACEINFOSTATUS(x) TRACEINFO << operation << L" status " << status << L" " << #x << std::endl
#define TRACEERRORSTATUS(x) TRACEERROR << operation << L" status " << status << L" " << #x << std::endl

    void TraceStatus(SECURITY_STATUS status, const std::wstring& operation = L"")
    {
        switch (status)
        {
        case SEC_E_OK:
            TRACEINFOSTATUS(SEC_E_OK);
            break;
        case SEC_I_COMPLETE_AND_CONTINUE:
            TRACEINFOSTATUS(SEC_I_COMPLETE_AND_CONTINUE);
            break;
        case SEC_I_COMPLETE_NEEDED:
            TRACEINFOSTATUS(SEC_I_COMPLETE_NEEDED);
            break;
        case SEC_I_CONTINUE_NEEDED:
            TRACEINFOSTATUS(SEC_I_CONTINUE_NEEDED);
            break;
        case SEC_I_INCOMPLETE_CREDENTIALS:
            TRACEINFOSTATUS(SEC_I_INCOMPLETE_CREDENTIALS);
            break;
        case SEC_E_INSUFFICIENT_MEMORY:
            TRACEERRORSTATUS(SEC_E_INSUFFICIENT_MEMORY);
            break;
        case SEC_E_INTERNAL_ERROR:
            TRACEERRORSTATUS(SEC_E_INTERNAL_ERROR);
            break;
        case SEC_E_INVALID_HANDLE:
            TRACEERRORSTATUS(SEC_E_INVALID_HANDLE);
            break;
        case SEC_E_INVALID_TOKEN:
            TRACEERRORSTATUS(SEC_E_INVALID_TOKEN);
            break;
        case SEC_E_LOGON_DENIED:
            TRACEERRORSTATUS(SEC_E_LOGON_DENIED);
            break;
        case SEC_E_NO_AUTHENTICATING_AUTHORITY:
            TRACEERRORSTATUS(SEC_E_NO_AUTHENTICATING_AUTHORITY);
            break;
        case SEC_E_NO_CREDENTIALS:
            TRACEERRORSTATUS(SEC_E_NO_CREDENTIALS);
            break;
        case SEC_E_NOT_OWNER:
            TRACEERRORSTATUS(SEC_E_NOT_OWNER);
            break;
        case SEC_E_SECPKG_NOT_FOUND:
            TRACEERRORSTATUS(SEC_E_SECPKG_NOT_FOUND);
            break;
        case SEC_E_UNKNOWN_CREDENTIALS:
            TRACEERRORSTATUS(SEC_E_UNKNOWN_CREDENTIALS);
            break;
        case SEC_E_TARGET_UNKNOWN:
            TRACEERRORSTATUS(SEC_E_TARGET_UNKNOWN);
            break;
        case SEC_E_UNSUPPORTED_FUNCTION:
            TRACEERRORSTATUS(SEC_E_UNSUPPORTED_FUNCTION);
            break;
        case SEC_E_WRONG_PRINCIPAL:
            TRACEERRORSTATUS(SEC_E_WRONG_PRINCIPAL);
            break;
        default:
            TRACEERRORSTATUS(L"");
            break;
        }
    }

    void TraceBuffer(const PSecBufferDesc buffer, const std::wstring& operation = L"")
    {
        if (buffer == nullptr)
        {
            TRACEINFO << operation << L" buffer is null" << std::endl;
            return;
        }

        TRACEINFO << operation << L" buffer [version|count] = [" << buffer->ulVersion << L"|" << buffer->cBuffers << L"]" << std::endl;

        for (unsigned long i = 0; i < buffer->cBuffers; i++)
        {
            TRACEINFO << operation << L" buffer[" << i << L"] [type|size] = [" << buffer->pBuffers[i].BufferType << L"|" << buffer->pBuffers[i].cbBuffer << L"]" << std::endl;
        }
    }

    virtual void TraceContext() = 0;

public:

    KerberosContext(std::wstring role, ULONG contextReq)
        : m_role(role), m_contextReq(contextReq)
    {
    }

    virtual ~KerberosContext()
    {
        SECURITY_STATUS status;

        if (m_ctxtHandle.dwLower != 0 || m_ctxtHandle.dwUpper != 0)
        {
            status = DeleteSecurityContext(&m_ctxtHandle);

            if (status == SEC_E_OK)
            {
                TRACEINFO << L"Deleted security context" << std::endl;
            }
            else
            {
                TRACEERROR << L"Failed to delete security context, error " << status << std::endl;
            }
        }

        if (m_credHandle.dwLower != 0 || m_credHandle.dwUpper != 0)
        {
            status = FreeCredentialsHandle(&m_credHandle);

            if (status == SEC_E_OK)
            {
                TRACEINFO << L"Freed credential handle" << std::endl;
            }
            else
            {
                TRACEERROR << L"Failed to free credential handle, error " << status << std::endl;
            }
        }
    }

    virtual SECURITY_STATUS AcquireCredential() = 0;
};

class Client : public KerberosContext
{
private:

    std::wstring m_serverPrincipal;

protected:

    virtual void TraceContext() override
    {
        TRACEINFO << L"Context handle " << m_ctxtHandle << std::endl;
        TRACEINFO << L"Context attributes 0x" << std::hex << m_contextAttr << std::dec;

#define FLAG(x) \
if (m_contextAttr & (x)) \
{ \
    std::wcout << L"|" << #x; \
}

        FLAG(ISC_RET_DELEGATE);
        FLAG(ISC_RET_MUTUAL_AUTH);
        FLAG(ISC_RET_REPLAY_DETECT);
        FLAG(ISC_RET_SEQUENCE_DETECT);
        FLAG(ISC_RET_CONFIDENTIALITY);
        FLAG(ISC_RET_USE_SESSION_KEY);
        FLAG(ISC_RET_USED_COLLECTED_CREDS);
        FLAG(ISC_RET_USED_SUPPLIED_CREDS);
        FLAG(ISC_RET_ALLOCATED_MEMORY);
        FLAG(ISC_RET_USED_DCE_STYLE);
        FLAG(ISC_RET_DATAGRAM);
        FLAG(ISC_RET_CONNECTION);
        FLAG(ISC_RET_INTERMEDIATE_RETURN);
        FLAG(ISC_RET_CALL_LEVEL);
        FLAG(ISC_RET_EXTENDED_ERROR);
        FLAG(ISC_RET_STREAM);
        FLAG(ISC_RET_INTEGRITY);
        FLAG(ISC_RET_IDENTIFY);
        FLAG(ISC_RET_NULL_SESSION);
        FLAG(ISC_RET_MANUAL_CRED_VALIDATION);
        FLAG(ISC_RET_RESERVED1);
        FLAG(ISC_RET_FRAGMENT_ONLY);
        FLAG(ISC_RET_FORWARD_CREDENTIALS);
        FLAG(ISC_RET_USED_HTTP_STYLE);
        FLAG(ISC_RET_NO_ADDITIONAL_TOKEN);
        FLAG(ISC_RET_REAUTHENTICATION);
        FLAG(ISC_RET_CONFIDENTIALITY_ONLY);
        FLAG(ISC_RET_MESSAGES);

#undef FLAG

        std::wcout << std::endl;
    }

public:
    Client(const std::wstring& serverPrincipal)
        : m_serverPrincipal(serverPrincipal),
        KerberosContext(
            L"Client",
            ISC_REQ_CONFIDENTIALITY
            | ISC_REQ_INTEGRITY
            | ISC_REQ_STREAM
            | ISC_REQ_USE_SESSION_KEY)
    {}

    virtual SECURITY_STATUS AcquireCredential() override
    {
        SECURITY_STATUS status;

        status = AcquireCredentialsHandleW(
            nullptr, /* pszPrincipal */
            const_cast<LPWSTR>(c_packageName.c_str()),
            SECPKG_CRED_OUTBOUND,
            nullptr, /* pvLogonID */
            nullptr, /* pAuthData */
            nullptr, /* pGetKeyFn */
            nullptr, /* pvGetKeyArgument */
            &m_credHandle,
            &m_expiry);

        if (status != SEC_E_OK)
        {
            TRACEERROR << L"Failed to acquire credential handle, error " << status << std::endl;
            return status;
        }

        std::wstring expirystr;
        TimeStampToUTCString(m_expiry, expirystr);
        TRACEINFO << L"Acquired credential handle " << m_credHandle << L", expiry " << expirystr << std::endl;
        return SEC_E_OK;
    }

    SECURITY_STATUS InitializeContext(
        PSecBufferDesc input,
        PSecBufferDesc output,
        bool& sendOutput)
    {
        SECURITY_STATUS status = SEC_E_OK;

        status = InitializeSecurityContextW(
            &m_credHandle,
            m_firstCall ? nullptr : &m_ctxtHandle,
            const_cast<SEC_WCHAR*>(m_serverPrincipal.c_str()),
            m_contextReq,
            0,
            c_targetDataRep,
            m_firstCall ? nullptr : input,
            0,
            &m_ctxtHandle,
            output,
            &m_contextAttr,
            &m_expiry);

        m_firstCall = false;
        TraceStatus(status, __FUNCTIONW__);
        TraceContext();
        TraceBuffer(output, __FUNCTIONW__);
        sendOutput = status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK && output->cBuffers > 0 && output->pBuffers[0].cbBuffer > 0;
        return status;
    }
};

class Server : public KerberosContext
{
private:
    std::wstring m_account;
    std::wstring m_domain;
    std::wstring m_password;
    std::wstring m_principal;

protected:

    virtual void TraceContext() override
    {
        TRACEINFO << L"Context handle " << m_ctxtHandle << std::endl;
        TRACEINFO << L"Context attributes 0x" << std::hex << m_contextAttr << std::dec;

#define FLAG(x) \
if (m_contextAttr & (x)) \
{ \
    std::wcout << L"|" << #x; \
}

        FLAG(ASC_RET_DELEGATE);
        FLAG(ASC_RET_MUTUAL_AUTH);
        FLAG(ASC_RET_REPLAY_DETECT);
        FLAG(ASC_RET_SEQUENCE_DETECT);
        FLAG(ASC_RET_CONFIDENTIALITY);
        FLAG(ASC_RET_USE_SESSION_KEY);
        FLAG(ASC_RET_SESSION_TICKET);
        FLAG(ASC_RET_ALLOCATED_MEMORY);
        FLAG(ASC_RET_USED_DCE_STYLE);
        FLAG(ASC_RET_DATAGRAM);
        FLAG(ASC_RET_CONNECTION);
        FLAG(ASC_RET_CALL_LEVEL);
        FLAG(ASC_RET_THIRD_LEG_FAILED);
        FLAG(ASC_RET_EXTENDED_ERROR);
        FLAG(ASC_RET_STREAM);
        FLAG(ASC_RET_INTEGRITY);
        FLAG(ASC_RET_LICENSING);
        FLAG(ASC_RET_IDENTIFY);
        FLAG(ASC_RET_NULL_SESSION);
        FLAG(ASC_RET_ALLOW_NON_USER_LOGONS);
        FLAG(ASC_RET_ALLOW_CONTEXT_REPLAY);
        FLAG(ASC_RET_FRAGMENT_ONLY);
        FLAG(ASC_RET_NO_TOKEN);
        FLAG(ASC_RET_NO_ADDITIONAL_TOKEN);
        FLAG(ASC_RET_MESSAGES);

#undef FLAG

        std::wcout << std::endl;
    }

public:
    Server(
        const std::wstring& principal,
        const std::wstring& account,
        const std::wstring& domain,
        const std::wstring& password)
        : m_principal(principal),
        m_account(account),
        m_domain(domain),
        m_password(password),
        KerberosContext(
            L"Server",
            ASC_REQ_CONFIDENTIALITY
            | ASC_REQ_INTEGRITY)
    {
    }

    virtual SECURITY_STATUS AcquireCredential() override
    {
        SECURITY_STATUS status;

        SEC_WINNT_AUTH_IDENTITY_W authId = {
            (unsigned short*)m_account.c_str(),
            (unsigned long)m_account.size(),
            (unsigned short*)m_domain.c_str(),
            (unsigned long)m_domain.size(),
            (unsigned short*)m_password.c_str(),
            (unsigned long)m_password.size(),
            SEC_WINNT_AUTH_IDENTITY_UNICODE};

        status = AcquireCredentialsHandleW(
            const_cast<SEC_WCHAR*>(m_principal.c_str()),
            const_cast<LPWSTR>(c_packageName.c_str()),
            SECPKG_CRED_INBOUND,
            nullptr, /* pvLognID */
            (PVOID)&authId,
            nullptr, /* pGetKeyFn */
            nullptr, /* pvGetKeyArgument */
            &m_credHandle,
            &m_expiry);

        if (status != SEC_E_OK)
        {
            TRACEERROR << L"Failed to acquire credential handle, error " << status << std::endl;
            return status;
        }

        std::wstring expirystr;
        TimeStampToUTCString(m_expiry, expirystr);
        TRACEINFO << L"Acquired credential handle " << m_credHandle << L", expiry " << expirystr << std::endl;
        return SEC_E_OK;
    }

    SECURITY_STATUS AcceptContext(
        PSecBufferDesc input,
        PSecBufferDesc output,
        bool& sendOutput)
    {
        SECURITY_STATUS status = SEC_E_OK;
        
        status = AcceptSecurityContext(
            &m_credHandle,
            m_firstCall ? nullptr : &m_ctxtHandle,
            input,
            m_contextReq,
            c_targetDataRep,
            &m_ctxtHandle,
            output,
            &m_contextAttr,
            &m_expiry);

        m_firstCall = false;
        TraceStatus(status, __FUNCTIONW__);
        TraceContext();
        TraceBuffer(output, __FUNCTIONW__);
        sendOutput = status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK && output->cBuffers > 0 && output->pBuffers[0].cbBuffer > 0;
        return status;
    }
};

int AuthenticateKerberos(
    const std::wstring& principal,
    const std::wstring& account,
    const std::wstring& domain,
    const std::wstring& password)
{
    SECURITY_STATUS status;
    std::vector<byte> clientToken(102400);
    std::vector<byte> serverToken(102400);
    SecBuffer clientTokenBuffer;
    SecBuffer serverTokenBuffer;
    SecBufferDesc clientBuffer;
    SecBufferDesc serverBuffer;
    Server server(principal, account, domain, password);
    Client client(principal);

    status = client.AcquireCredential();

    if (status != SEC_E_OK)
    {
        std::wcerr << L"Failed to acquire client credential, error " << status << std::endl;
        return status;
    }

    status = server.AcquireCredential();

    if (status != SEC_E_OK)
    {
        std::wcerr << L"Failed to acquire server credential, error " << status << std::endl;
        return status;
    }

    clientBuffer.ulVersion = 0;
    clientBuffer.cBuffers = 1;
    clientBuffer.pBuffers = &clientTokenBuffer;
    clientBuffer.pBuffers[0].BufferType = SECBUFFER_TOKEN;
    clientBuffer.pBuffers[0].cbBuffer = (unsigned long)clientToken.size();
    clientBuffer.pBuffers[0].pvBuffer = clientToken.data();

    serverBuffer.ulVersion = 0;
    serverBuffer.cBuffers = 1;
    serverBuffer.pBuffers = &serverTokenBuffer;
    serverBuffer.pBuffers[0].BufferType = SECBUFFER_TOKEN;
    serverBuffer.pBuffers[0].cbBuffer = (unsigned long)serverToken.size();
    serverBuffer.pBuffers[0].pvBuffer = serverToken.data();

    bool sendToken{ false };

    do {
        serverBuffer.pBuffers[0].cbBuffer = (unsigned long)serverToken.size();
        status = client.InitializeContext(&clientBuffer, &serverBuffer, sendToken);

        if (sendToken)
        {
            clientBuffer.pBuffers[0].cbBuffer = (unsigned long)clientToken.size();
            status = server.AcceptContext(&serverBuffer, &clientBuffer, sendToken);
        }
    } while (sendToken);

    return status;
}

void Usage(wchar_t* argv[])
{
    std::wcout << argv[0] << L" ep" << std::endl;
    std::wcout << argv[0] << L" kerb <principal> <account> <domain> <password>" << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc == 1 || argv[1][0] == L'?')
    {
        Usage(argv);
        return S_OK;
    }

    std::wstring command = argv[1];

    if (command == L"ep")
    {
        return EnumPackages();
    }
    else if (command == L"kerb" && argc == 6)
    {
        return AuthenticateKerberos(argv[2], argv[3], argv[4], argv[5]);
    }
    else
    {
        Usage(argv);
        return ERROR_BAD_ARGUMENTS;
    }

    return S_OK;
}
