// ExceptionTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <exception>
#include <iostream>
#include <map>
#include <string>

#define FUNC_BEGIN std::wcout << L"[" << __func__ << L"] Begin" << std::endl
#define FUNC_END std::wcout << L"[" << __func__ << L"] End" << std::endl
#define FUNC_TRACE std::wcout << L"[" << __func__ << L"] "

void DivideByZero()
{
    FUNC_BEGIN;
    int x = 10;
    int y = 0;
    int r = x / y;
    FUNC_END;
}

void SehDivideByZeroHandleException()
{
    FUNC_BEGIN;
    __try
    {
        DivideByZero();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        FUNC_TRACE << L"Exception: " << GetExceptionCode() << std::endl;
    }
    FUNC_END;
}

void CppDivideByZeroHandleException()
{
    FUNC_BEGIN;
    try
    {
        DivideByZero();
    }
    catch (std::exception& e)
    {
        FUNC_TRACE << L"Exception: " << e.what() << std::endl;
    }
    catch (...)
    {
        FUNC_TRACE << L"Exception: ..." << std::endl;
    }
    FUNC_END;
}

const std::map<int, std::pair<void(*)(), std::wstring>> TestCase =
{
    {
        0,
        {
            SehDivideByZeroHandleException,
            L"Structured exception handler on divide-by-zero"
        }
    },
    {
        1,
        {
            CppDivideByZeroHandleException,
            L"CPP exception handle on divide-by-zero"
        }
    }
};

void Usage()
{
    std::wcout << L"ExceptionTest.exe [Test Case #]" << std::endl;
    std::wcout << L"Test Case List:" << std::endl;
    for (const auto& test : TestCase)
    {
        std::wcout << test.first << L": " << test.second.second << std::endl;
    }
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        Usage();
        return S_FALSE;
    }

    int test = std::stoi(argv[1]);

    if (TestCase.find(test) == TestCase.end())
    {
        std::wcout << L"Unknown test case " << test << std::endl;
        return E_FAIL;
    }

    FUNC_BEGIN;
    TestCase.at(test).first();
    FUNC_END;
    return S_OK;
}