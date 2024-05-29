#include <Windows.h>
#include <bcrypt.h>
#include <iostream>

#pragma comment(lib, "bcrypt")

template<typename T>
HRESULT GetAlgorithmProperty(
    BCRYPT_HANDLE hAlg,
    LPCWSTR propertyName,
    std::unique_ptr<byte[]>& propertyBuffer,
    T** property,
    PULONG propertySize = nullptr)
{
    NTSTATUS status;
    ULONG propertySizeLocal = 0;

    status = BCryptGetProperty(
        hAlg,
        propertyName,
        nullptr, /* pbOutput */
        0, /* cbOutput */
        &propertySizeLocal,
        0 /* dwFlags */);

    // BCryptGetProperty returns STATUS_SUCCESS instead of STATUS_BUFFER_TOO_SMALL when pbOutput is null
    if (status != 0)
    {
        std::wcerr << L"Failed to get property size: status=" << status << std::endl;
        return HRESULT_FROM_NT(status);
    }

    propertyBuffer.reset(new byte[propertySizeLocal]);

    status = BCryptGetProperty(
        hAlg,
        propertyName,
        propertyBuffer.get(),
        propertySizeLocal,
        &propertySizeLocal,
        0 /* dwFlags */);

    if (status != 0)
    {
        std::wcerr << L"Failed to get property value: status=" << status << std::endl;
        return HRESULT_FROM_NT(status);
    }

    *property = (T *)(propertyBuffer.get());

    if (propertySize != nullptr)
    {
        *propertySize = propertySizeLocal;
    }

    return S_OK;
}

HRESULT GetAlgorithmName(BCRYPT_ALG_HANDLE hAlg)
{
    HRESULT hr;
    std::unique_ptr<byte[]> propertyBuffer;
    LPWSTR name;

    hr = GetAlgorithmProperty(hAlg, BCRYPT_ALGORITHM_NAME, propertyBuffer, &name);

    if (FAILED(hr))
    {
        std::wcerr << L"GetAlgorithmName failed: hr=" << hr << std::endl;
        return hr;
    }

    std::wcout << L"Algorithm name: '" << name << L"'" << std::endl;
    return S_OK;
}

HRESULT GetAlgorithmAuthTagLength(BCRYPT_ALG_HANDLE hAlg)
{
    HRESULT hr;
    std::unique_ptr<byte[]> propertyBuffer;
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT* property;

    hr = GetAlgorithmProperty(hAlg, BCRYPT_AUTH_TAG_LENGTH, propertyBuffer, &property);

    if (FAILED(hr))
    {
        std::wcerr << L"GetAlgorithmAuthTagLength failed: hr=" << hr << std::endl;
        return hr;
    }

    std::wcout << L"Algorithm auth tag length [min|max|inc] = [" << property->dwMinLength << L"|" << property->dwMaxLength << L"|" << property->dwIncrement << L"]" << std::endl;
    return S_OK;
}

HRESULT GetAlgorithmBlockLength(BCRYPT_ALG_HANDLE hAlg)
{
    HRESULT hr;
    std::unique_ptr<byte[]> propertyBuffer;
    DWORD* property;

    hr = GetAlgorithmProperty(hAlg, BCRYPT_BLOCK_LENGTH, propertyBuffer, &property);

    if (FAILED(hr))
    {
        std::wcerr << L"GetAlgorithmBlockLength failed: hr=" << hr << std::endl;
        return hr;
    }

    std::wcout << L"Algorithm block length  = " << *property << std::endl;
    return S_OK;
}

HRESULT GetAlgorithmBlockSizeList(BCRYPT_ALG_HANDLE hAlg)
{
    HRESULT hr;
    std::unique_ptr<byte[]> propertyBuffer;
    DWORD* property;
    ULONG propertySize = 0;

    hr = GetAlgorithmProperty(hAlg, BCRYPT_BLOCK_SIZE_LIST, propertyBuffer, &property, &propertySize);

    if (FAILED(hr))
    {
        std::wcerr << L"GetAlgorithmBlockSizeList failed: hr=" << hr << std::endl;
        return hr;
    }

    size_t sizesCount = (size_t)propertySize / sizeof(DWORD);
    std::wcout << L"Algorithm block sizes  = [";
    for (size_t i = 0; i < sizesCount; i++)
    {
        if (i > 0)
        {
            std::wcout << L",";
        }
        std::wcout << property[i];
    }
    std::wcout << L"]" << std::endl;
    return S_OK;
}

HRESULT GetAlgorithmChainingMode(BCRYPT_ALG_HANDLE hAlg)
{
    HRESULT hr;
    std::unique_ptr<byte[]> propertyBuffer;
    LPWSTR mode;

    hr = GetAlgorithmProperty(hAlg, BCRYPT_CHAINING_MODE, propertyBuffer, &mode);

    if (FAILED(hr))
    {
        std::wcerr << L"GetAlgorithmChainingMode failed: hr=" << hr << std::endl;
        return hr;
    }

    std::wcout << L"Algorithm chaininng mode: '" << mode << L"'" << std::endl;
    return S_OK;
}


HRESULT InspectAlgorithmProvider(
    LPCWSTR algorithmId,
    LPCWSTR implementation = MS_PRIMITIVE_PROVIDER,
    ULONG flag = 0)
{
    NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlg = INVALID_HANDLE_VALUE;

    std::wcout << L"Algorithm " << algorithmId << L" implementation " << implementation << L" flag " << flag << std::endl;

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

    std::wcout << L"Opened handle=0x" << std::hex << hAlg << std::dec << std::endl;

    GetAlgorithmName(hAlg);
    GetAlgorithmAuthTagLength(hAlg);
    GetAlgorithmBlockLength(hAlg);
    GetAlgorithmBlockSizeList(hAlg);
    GetAlgorithmChainingMode(hAlg);

    status = BCryptCloseAlgorithmProvider(hAlg, 0 /* dwFlags */);

    if (status != 0)
    {
        std::wcerr << L"BCryptCloseAlgorithmProvider failed: status=" << status << std::endl;
        return HRESULT_FROM_NT(status);
    }

    std::wcout << L"Cloded handle=0x" << std::hex << hAlg << std::dec << std::endl;

    hAlg = INVALID_HANDLE_VALUE;
    return S_OK;
}

HRESULT InspectAlgorithmProviders(
    LPCWSTR implementation = MS_PRIMITIVE_PROVIDER)
{
    InspectAlgorithmProvider(BCRYPT_RSA_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_RSA_SIGN_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_DH_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_DSA_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_RC2_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_RC4_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_AES_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_DES_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_DESX_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_3DES_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_3DES_112_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_MD2_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_MD4_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_MD5_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_SHA1_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_SHA256_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_SHA384_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_SHA512_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_AES_GMAC_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_AES_CMAC_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_ECDSA_P256_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_ECDSA_P384_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_ECDSA_P521_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_ECDH_P256_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_ECDH_P384_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_ECDH_P521_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_RNG_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_RNG_FIPS186_DSA_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_RNG_DUAL_EC_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_SP800108_CTR_HMAC_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_SP80056A_CONCAT_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_PBKDF2_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_CAPI_KDF_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_TLS1_1_KDF_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_TLS1_2_KDF_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_ECDSA_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_ECDH_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_XTS_AES_ALGORITHM, implementation);
    InspectAlgorithmProvider(BCRYPT_HKDF_ALGORITHM, implementation);

    return S_OK;
}


int wmain(int argc, wchar_t** argv)
{
    HRESULT hr = S_OK;
    InspectAlgorithmProviders();
    // InspectAlgorithmProviders(MS_PLATFORM_CRYPTO_PROVIDER);
    return hr;
}
