#pragma once

using namespace System;
using namespace System::Runtime::InteropServices;

namespace CliPInvoke {

	public ref class Native
	{
	public:
		[DllImport("CppDll.dll")]
    	static int CGetStringLength([MarshalAs(UnmanagedType::LPWStr)]String^);
	};
}
