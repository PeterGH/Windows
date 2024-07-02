#pragma once

#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <string>

#ifdef IMPORTING
#define CPPDLL_DECLSPEC __declspec(dllimport)
#else
#define CPPDLL_DECLSPEC __declspec(dllexport)
#endif // IMPORTING

namespace CppDll
{
#define TRACE_FUNCTION std::wcout << __FUNCTION__ << std::endl;

	class CPPDLL_DECLSPEC TestClass
	{
	public:
		TestClass();
		~TestClass();

		int GetStringLength(const std::wstring& x);
	};
}

extern "C" {
	CPPDLL_DECLSPEC int CGetStringLength(LPCWSTR x);
}

