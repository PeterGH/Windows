#include <Windows.h>
#include <bcrypt.h>
#include <iostream>

#pragma comment(lib, "bcrypt")

int InspectAlgorithmProvider(
    LPCWSTR algorithmId,
    LPCWSTR implementation = MS_PRIMITIVE_PROVIDER,
    ULONG flag = 0)
{
    NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlg = INVALID_HANDLE_VALUE;

    status = BCryptOpenAlgorithmProvider(&hAlg, algorithmId, implementation, flag);

    if (status != 0)
    {
        std::wcerr << L"BCryptOpenAlgorithmProvider failed: status=" << status << std::endl;
        return HRESULT_FROM_NT(status);
    }

    if (hAlg == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"BCryptOpenAlgorithmProvider returned an invalid handle." << std::endl;
        return HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE);
    }

    std::wcout << L"Opened algorithm " << algorithmId << L" implementation " << implementation << L" with flag " << flag << L", handle=0x" << std::hex << hAlg << std::dec << std::endl;

    status = BCryptCloseAlgorithmProvider(hAlg, 0 /* dwFlags */);

    if (status != 0)
    {
        std::wcerr << L"BCryptCloseAlgorithmProvider failed: status=" << status << std::endl;
        return HRESULT_FROM_NT(status);
    }

    std::wcout << L"Clodes algorithm " << algorithmId << L" implementation " << implementation << L" with flag " << flag << L", handle=0x" << std::hex << hAlg << std::dec << std::endl;

    hAlg = INVALID_HANDLE_VALUE;
    return S_OK;
}

int wmain(int argc, wchar_t** argv)
{
    HRESULT hr = S_OK;

    InspectAlgorithmProvider(BCRYPT_3DES_ALGORITHM);

    return hr;
}
