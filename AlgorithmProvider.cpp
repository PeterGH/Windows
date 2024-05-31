#include <Windows.h>
#include <bcrypt.h>
#include <iostream>
#include <sstream>

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

    std::wcout << L"Algorithm " << BCRYPT_ALGORITHM_NAME << L" = '" << name << L"'" << std::endl;
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

    std::wcout << L"Algorithm " << BCRYPT_AUTH_TAG_LENGTH << L": [min | max | inc] = [" << property->dwMinLength << L" | " << property->dwMaxLength << L" | " << property->dwIncrement << L"]" << std::endl;
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

    std::wcout << L"Algorithm " << BCRYPT_BLOCK_LENGTH << L" = " << *property << std::endl;
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
    std::wcout << L"Algorithm " << BCRYPT_BLOCK_SIZE_LIST << L" = [";
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

    std::wcout << L"Algorithm " << BCRYPT_CHAINING_MODE << L" = '" << mode << L"'" << std::endl;
    return S_OK;
}

std::wstring ToString(byte* buffer, ULONG length)
{
    std::wostringstream oss;

    oss << std::hex;

    for (ULONG i = 0; i < length; i++)
    {
        oss << buffer[i++];
    }

    return oss.str();
}

HRESULT GetAlgorithmDhParameters(BCRYPT_ALG_HANDLE hAlg)
{
    HRESULT hr;
    std::unique_ptr<byte[]> propertyBuffer;
    BCRYPT_DH_PARAMETER_HEADER* property;
    ULONG propertySize = 0;

    hr = GetAlgorithmProperty(hAlg, BCRYPT_DH_PARAMETERS, propertyBuffer, &property, &propertySize);

    if (FAILED(hr))
    {
        std::wcerr << L"GetAlgorithmDhParameters failed: hr=" << hr << std::endl;
        return hr;
    }

    std::wcout << L"Algorithm " << BCRYPT_DH_PARAMETERS << L": [Length | Magic | KeyLength] = ['" << property->cbLength << L"|0x" << std::hex << property->dwMagic << std::dec << L"|" << property->cbKeyLength << L"]" << std::endl;

    if (property->cbLength != propertySize)
    {
        std::wcerr << L"GetAlgorithmDhParameters unexpected buffer size: expected=" << propertySize << L", actual=" << property->cbLength << std::endl;
    }

    if (property->dwMagic != 0x4d504844)
    {
        std::wcerr << L"GetAlgorithmDhParameters unexpected magic number: expected=0x4d504844, actual=0x" << std::hex << property->dwMagic << std::dec << std::endl;
    }

    ULONG expectedKeyLength = (propertySize - sizeof(BCRYPT_DH_PARAMETER_HEADER)) >> 1;

    if (property->cbKeyLength != expectedKeyLength)
    {
        std::wcerr << L"GetAlgorithmDhParameters unexpected key length: expected=" << expectedKeyLength << L", actual=" << property->cbKeyLength << std::endl;
    }

    PBYTE key = (PBYTE)(property + sizeof(BCRYPT_DH_PARAMETER_HEADER));
    std::wcout << L"Algorithm " << BCRYPT_DH_PARAMETERS << L": Prime=0x" << ToString(key, property->cbKeyLength) << std::endl;
    key += property->cbKeyLength;
    std::wcout << L"Algorithm " << BCRYPT_DH_PARAMETERS << L": Generator=0x" << ToString(key, property->cbKeyLength) << std::endl;

    return S_OK;
}

HRESULT GetAlgorithmEffectiveKeyLength(BCRYPT_ALG_HANDLE hAlg)
{
    HRESULT hr;
    std::unique_ptr<byte[]> propertyBuffer;
    DWORD* property;

    hr = GetAlgorithmProperty(hAlg, BCRYPT_EFFECTIVE_KEY_LENGTH, propertyBuffer, &property);

    if (FAILED(hr))
    {
        std::wcerr << L"GetAlgorithmEffectiveKeyLength failed: hr=" << hr << std::endl;
        return hr;
    }

    std::wcout << L"Algorithm " << BCRYPT_EFFECTIVE_KEY_LENGTH << L" = " << *property << std::endl;
    return S_OK;
}

HRESULT GetAlgorithmHashBlockLength(BCRYPT_ALG_HANDLE hAlg)
{
    HRESULT hr;
    std::unique_ptr<byte[]> propertyBuffer;
    DWORD* property;

    hr = GetAlgorithmProperty(hAlg, BCRYPT_HASH_BLOCK_LENGTH, propertyBuffer, &property);

    if (FAILED(hr))
    {
        std::wcerr << L"GetAlgorithmHashBlockLength failed: hr=" << hr << std::endl;
        return hr;
    }

    std::wcout << L"Algorithm " << BCRYPT_HASH_BLOCK_LENGTH << L" = " << *property << std::endl;
    return S_OK;
}

HRESULT GetAlgorithmHashLength(BCRYPT_ALG_HANDLE hAlg)
{
    HRESULT hr;
    std::unique_ptr<byte[]> propertyBuffer;
    DWORD* property;

    hr = GetAlgorithmProperty(hAlg, BCRYPT_HASH_LENGTH, propertyBuffer, &property);

    if (FAILED(hr))
    {
        std::wcerr << L"GetAlgorithmHashLength failed: hr=" << hr << std::endl;
        return hr;
    }

    std::wcout << L"Algorithm " << BCRYPT_HASH_LENGTH << L" = " << *property << std::endl;
    return S_OK;
}

HRESULT GetAlgorithmHashOidList(BCRYPT_ALG_HANDLE hAlg)
{
    HRESULT hr;
    std::unique_ptr<byte[]> propertyBuffer;
    BCRYPT_OID_LIST* property;
    ULONG propertySize = 0;

    hr = GetAlgorithmProperty(hAlg, BCRYPT_HASH_OID_LIST, propertyBuffer, &property, &propertySize);

    if (FAILED(hr))
    {
        std::wcerr << L"GetAlgorithmHashOidList failed: hr=" << hr << std::endl;
        return hr;
    }

    std::wcout << L"Algorithm " << BCRYPT_HASH_OID_LIST << L": Count = " << property->dwOIDCount << std::endl;

    ULONG actualSize = sizeof(property->dwOIDCount) + property->dwOIDCount * sizeof(BCRYPT_OID);
    for (ULONG i = 0; i < property->dwOIDCount; i++)
    {
        BCRYPT_OID* oid = &property->pOIDs[i];
        actualSize += oid->cbOID;
        std::wcout << L"Algorithm " << BCRYPT_HASH_OID_LIST << L"[" << i << L"] = " << ToString(oid->pbOID, oid->cbOID) << std::endl;
    }

    if (actualSize != propertySize)
    {
        std::wcerr << L"GetAlgorithmHashOidList unexpected buffer size: expected=" << propertySize << L", actual=" << actualSize << std::endl;
    }

    return S_OK;
}

HRESULT InspectAlgorithmProvider(
    LPCWSTR algorithmId,
    LPCWSTR implementation = MS_PRIMITIVE_PROVIDER,
    ULONG flag = 0)
{
    NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlg = INVALID_HANDLE_VALUE;

    std::wcout << L"============================================================================" << std::endl;
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

    GetAlgorithmName(hAlg);
    GetAlgorithmAuthTagLength(hAlg);
    GetAlgorithmBlockLength(hAlg);
    GetAlgorithmBlockSizeList(hAlg);
    GetAlgorithmChainingMode(hAlg);
    GetAlgorithmDhParameters(hAlg);
    GetAlgorithmEffectiveKeyLength(hAlg);
    GetAlgorithmHashBlockLength(hAlg);
    GetAlgorithmHashLength(hAlg);
    GetAlgorithmHashOidList(hAlg);

    status = BCryptCloseAlgorithmProvider(hAlg, 0 /* dwFlags */);

    if (status != 0)
    {
        std::wcerr << L"BCryptCloseAlgorithmProvider failed: status=" << status << std::endl;
        return HRESULT_FROM_NT(status);
    }

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
