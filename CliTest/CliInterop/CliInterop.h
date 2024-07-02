#pragma once

#define IMPORTING
#include "CppDll.h"
#undef IMPORTING

using namespace System;

namespace CliInterop {
	public ref class MTestClass
	{
	private:
		CppDll::TestClass* m_impl;
	public:
		MTestClass();
		~MTestClass();
		!MTestClass();

		int GetStringLength(String^ x);
		int GetStringLength2(String^ x);
		int GetStringLength3(String^ x);
		int GetStringLength4(String^ x);
	};
}
