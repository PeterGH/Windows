#include <Windows.h>
#include <exception>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>

#define FUNC_BEGIN std::wcout << L"[" << __func__ << L"] Begin" << std::endl
#define FUNC_END std::wcout << L"[" << __func__ << L"] End" << std::endl
#define FUNC_TRACE std::wcout << L"[" << __func__ << L"] "

void DivideByZero(void)
{
    FUNC_BEGIN;
    int x = 10;
    int y = 0;
    int r = x / y;
    FUNC_END;
}

void RunTimeError(void)
{
    FUNC_BEGIN;
    throw std::runtime_error("Hit a runtime error");
    FUNC_END;
}

class application_error : public std::runtime_error
{
public:
    application_error(const std::string& what) : std::runtime_error(what)
    {
        FUNC_TRACE << "application_error()" << std::endl;
    }

    ~application_error()
    {
        FUNC_TRACE << "~application_error()" << std::endl;
    }
};

void ApplicationError(void)
{
    FUNC_BEGIN;
    throw application_error("Hit an application error");
    FUNC_END;
}

#define EXCEPTION_CODE_ENTRY(x) {x, #x}

const std::map<int, std::string> EXCEPTIONCODE =
{
    EXCEPTION_CODE_ENTRY(EXCEPTION_ACCESS_VIOLATION),
    EXCEPTION_CODE_ENTRY(EXCEPTION_INT_DIVIDE_BY_ZERO)
};

std::wstring GetExceptionCodeString(int exceptionCode)
{
    if (EXCEPTIONCODE.find(exceptionCode) == EXCEPTIONCODE.end())
    {
        return std::to_wstring(exceptionCode);
    }
    const std::string& result = EXCEPTIONCODE.at(exceptionCode);
    return std::wstring(result.cbegin(), result.cend());
}

void ProcessExceptionRecord(PEXCEPTION_RECORD exceptionRecord)
{
    FUNC_BEGIN;
    if (exceptionRecord != nullptr)
    {
        FUNC_TRACE << L"ExceptionCode: " << exceptionRecord->ExceptionCode << std::endl;
        FUNC_TRACE << L"ExceptionFlags: 0x" << std::hex << exceptionRecord->ExceptionFlags << std::dec << std::endl;
        FUNC_TRACE << L"ExceptionAddress: 0x" << std::hex << exceptionRecord->ExceptionAddress << std::dec << std::endl;
        if (exceptionRecord->NumberParameters > 0)
        {
            FUNC_TRACE << L"NumberParameters: " << exceptionRecord->NumberParameters << std::endl;
            for (DWORD i = 0; i < exceptionRecord->NumberParameters; i++)
            {
                FUNC_TRACE << L"ExceptionInformation[" << i << L"]: 0x" << std::hex << exceptionRecord->ExceptionInformation[i] << std::dec << std::endl;
            }
        }
        if (exceptionRecord->ExceptionRecord != nullptr)
        {
            FUNC_TRACE << L"Inner Exception ========" << std::endl;
            ProcessExceptionRecord(exceptionRecord->ExceptionRecord);
        }
    }
    FUNC_END;
}

LONG ExceptionFilter(LPEXCEPTION_POINTERS exceptionInfo)
{
    FUNC_BEGIN;
    if (exceptionInfo != nullptr)
    {
        if (exceptionInfo->ExceptionRecord != nullptr)
        {
            ProcessExceptionRecord(exceptionInfo->ExceptionRecord);
        }
        if (exceptionInfo->ContextRecord != nullptr)
        {
        }
    }
    FUNC_END;
    return EXCEPTION_EXECUTE_HANDLER;
}

void SehDivideByZeroHandleException(void)
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

void CppDivideByZeroCatchException(void)
{
    FUNC_BEGIN;
    try
    {
        // Windows exception will not be caught by C++ catch clause,
        // instead it will be caught by SEH handler in RunTest.
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

void SehRunTimeErrorHandleException(void)
{
    FUNC_BEGIN;
    __try
    {
        RunTimeError();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        FUNC_TRACE << L"Exception: " << GetExceptionCode() << std::endl;
    }
    FUNC_END;
}

void CppRunTimeErrorCatchException(void)
{
    FUNC_BEGIN;
    try
    {
        RunTimeError();
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

void SehApplicationErrorHandleException(void)
{
    FUNC_BEGIN;
    __try
    {
        ApplicationError();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        FUNC_TRACE << L"Exception: " << GetExceptionCode() << std::endl;
    }
    FUNC_END;
}

void CppApplicationErrorCatchException(void)
{
    FUNC_BEGIN;
    try
    {
        ApplicationError();
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

typedef void(*TEST_METHOD)(void);

const std::map<int, std::pair<TEST_METHOD, std::wstring>> TestCase =
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
            CppDivideByZeroCatchException,
            L"CPP exception catch on divide-by-zero"
        }
    },
    {
        2,
        {
            SehRunTimeErrorHandleException,
            L"Structured exception handler on cpp runtime_error"
        }
    },
    {
        3,
        {
            CppRunTimeErrorCatchException,
            L"CPP exception catch cpp runtime_error"
        }
    },
    {
        4,
        {
            SehApplicationErrorHandleException,
            L"Structured exception handler on cpp custom application error"
        }
    },
    {
        5,
        {
            CppApplicationErrorCatchException,
            L"CPP exception catch cpp custom application error"
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

void RunTest(TEST_METHOD test)
{
    FUNC_BEGIN;
    __try
    {
        test();
    }
    __except (ExceptionFilter(GetExceptionInformation()))
    {
        FUNC_TRACE << L"Exception: " << GetExceptionCode() << std::endl;
    }
    FUNC_END;
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
    RunTest(TestCase.at(test).first);
    FUNC_END;
    return S_OK;
}