#include "pch.h"
#include "CppDll.h"

namespace CppDll
{
	TestClass::TestClass()
	{
		TRACE_FUNCTION;
	}

	TestClass::~TestClass()
	{
		TRACE_FUNCTION;
	}

	int TestClass::GetStringLength(const std::wstring& x)
	{
		TRACE_FUNCTION;
		return static_cast<int>(x.size());
	}
}

int CGetStringLength(LPCWSTR x)
{
	TRACE_FUNCTION;
	int length = static_cast<int>(wcslen(x));
	return length;
}
