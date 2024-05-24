#include <Windows.h>
#include <bcrypt.h>
#include <iostream>

#pragma comment(lib, "bcrypt")

int wmain(int argc, wchar_t** argv)
{
    NTSTATUS status;
    ULONG cbBuffer = 0;
    PCRYPT_PROVIDERS pBuffer = nullptr;

    status = BCryptEnumRegisteredProviders(&cbBuffer, &pBuffer);
    if (status == 0 && pBuffer != nullptr)
    {
        std::wcout << L"Found " << pBuffer->cProviders << L" providers:" << std::endl;
        for (ULONG i = 0; i < pBuffer->cProviders; i++)
        {
            std::wcout << pBuffer->rgpszProviders[i] << std::endl;
        }
    }
    else
    {
        std::wcerr << L"BCryptEnumRegisteredProviders failed: status=" << status << std::endl;
    }

    if (pBuffer != nullptr)
    {
        BCryptFreeBuffer(pBuffer);
        pBuffer = nullptr;
    }

    return HRESULT_FROM_NT(status);
}
