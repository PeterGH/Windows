#include "pch.h"
#include <msclr\marshal.h>
#include <msclr\marshal_windows.h>
#include <msclr\marshal_cppstd.h>
#include <vcclr.h>
#include "CliInterop.h"

namespace CliInterop
{
	MTestClass::MTestClass()
	{
		Console::WriteLine(__FUNCTION__);
		m_impl = new CppDll::TestClass();
	}

	MTestClass::~MTestClass()
	{
		Console::WriteLine(__FUNCTION__);
		this->!MTestClass();
	}

	MTestClass::!MTestClass()
	{
		Console::WriteLine(__FUNCTION__);
		delete m_impl;
		m_impl = nullptr;
	}

	int MTestClass::GetStringLength(String^ x)
	{
		Console::WriteLine(__FUNCTION__);
		pin_ptr<const wchar_t> s = PtrToStringChars(x);
		int length = m_impl->GetStringLength(s);
		return length;
	}

	int MTestClass::GetStringLength2(String^ x)
	{
		Console::WriteLine(__FUNCTION__);
		IntPtr s = System::Runtime::InteropServices::Marshal::StringToHGlobalUni(x);
		int length = m_impl->GetStringLength(static_cast<wchar_t*>(s.ToPointer()));
		System::Runtime::InteropServices::Marshal::FreeHGlobal(s);
		return length;
	}

	int MTestClass::GetStringLength3(String^ x)
	{
		Console::WriteLine(__FUNCTION__);
		int length = m_impl->GetStringLength(msclr::interop::marshal_as<std::wstring>(x));
		return length;
	}

	int MTestClass::GetStringLength4(String^ x)
	{
		Console::WriteLine(__FUNCTION__);
		msclr::interop::marshal_context^ context = gcnew msclr::interop::marshal_context();
		int length = m_impl->GetStringLength(context->marshal_as<const wchar_t*>(x));
		return length;
	}
}
