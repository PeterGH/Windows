#include <WinSock2.h>
#include <Windows.h>
#include <WS2spi.h>
#include <WS2tcpip.h>
#include <nsemail.h>
#include <iomanip>
#include <ios>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

#define BEGIN_FUNCTION std::wcout << L"[" << GetSystemTimeString() << L"][" << ::GetCurrentThreadId() << L"] "<< __FUNCTION__ << L" Begin" << std::endl
#define TRACE_FUNCTION std::wcout << L"[" << GetSystemTimeString() << L"][" << ::GetCurrentThreadId() << L"] "<< __FUNCTION__ << L": "
#define END_FUNCTION std::wcout << L"[" << GetSystemTimeString() << L"][" << ::GetCurrentThreadId() << L"] "<< __FUNCTION__ << L" End" << std::endl

std::wstring GetSystemTimeString()
{
	DWORD error = ERROR_SUCCESS;
	SYSTEMTIME st;
	std::wstring date;
	std::wstring time;
	int length;

	::GetSystemTime(&st);

	length = ::GetDateFormatEx(
		LOCALE_NAME_SYSTEM_DEFAULT,
		0,
		&st,
		L"yyyy-MM-dd",
		nullptr,
		0,
		nullptr);

	if (length == 0)
	{
		error = GetLastError();
		std::wcerr << L"GetDateFormatEx failed to get the required length, error=" << error << std::endl;
	}
	else
	{
		date.resize(length);

		length = ::GetDateFormatEx(
			LOCALE_NAME_SYSTEM_DEFAULT,
			0,
			&st,
			L"yyyy-MM-dd",
			const_cast<wchar_t*>(date.c_str()),
			length,
			nullptr);

		if (length == 0)
		{
			error = GetLastError();
			std::wcerr << L"GetDateFormatEx failed to get the date string, error=" << error << std::endl;
		}
	}

	if (length == 0)
	{
		std::wostringstream oss;
		oss << st.wYear << L"-" << st.wMonth << L"-" << st.wDay;
		date.assign(oss.str());
	}

	length = ::GetTimeFormatEx(
		LOCALE_NAME_SYSTEM_DEFAULT,
		TIME_FORCE24HOURFORMAT,
		&st,
		L"HH:mm:ss",
		nullptr,
		0);

	if (length == 0)
	{
		error = GetLastError();
		std::wcerr << L"GetTimeFormatEx failed to get the required length, error=" << error << std::endl;
	}
	else
	{
		time.resize(length);

		length = ::GetTimeFormatEx(
			LOCALE_NAME_SYSTEM_DEFAULT,
			TIME_FORCE24HOURFORMAT,
			&st,
			L"HH:mm:ss",
			const_cast<wchar_t*>(time.c_str()),
			length);

		if (length == 0)
		{
			error = GetLastError();
			std::wcerr << L"GetTimeFormatEx failed to get the time string, error=" << error << std::endl;
		}
	}

	if (length == 0)
	{
		std::wostringstream oss;
		oss << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L"." << st.wMilliseconds;
		time.assign(oss.str());
	}

	return date + L" " + time;
}

std::wstring ToWString(std::string str)
{
	std::wstring wstr(str.cbegin(), str.cend());
	return wstr;
}

DWORD GetSockAddrIn(const std::wstring& ip, u_short port, sockaddr_in& addr)
{
	DWORD error = ERROR_SUCCESS;
	in_addr ia;
	error = InetPton(AF_INET, ip.c_str(), &ia);

	if (error == 1)
	{
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = ia.s_addr;
		addr.sin_port = htons(port);
		std::wcout << L"sockaddr_in.[sin_family|sin_addr|sin_port] = [" << addr.sin_family << L"|0x" << std::hex << addr.sin_addr.s_addr << L"|0x" << addr.sin_port << std::dec << L"]" << std::endl;
		error = ERROR_SUCCESS;
	}
	else if (error == 0)
	{
		error = ERROR_INVALID_PARAMETER;
	}
	else if (error == -1)
	{
		error = WSAGetLastError();
	}

	return error;
}

void Print(const WSADATA& wsaData)
{
	std::wcout << L"wVersion: 0x" << std::hex << wsaData.wVersion << std::dec << std::endl;
	std::wcout << L"wHighVersion: 0x" << std::hex << wsaData.wHighVersion << std::dec << std::endl;
	std::wcout << L"iMaxSockets: " << wsaData.iMaxSockets << std::endl;
	std::wcout << L"iMaxUdpDg: " << wsaData.iMaxUdpDg << std::endl;
	/*if (wsaData.lpVendorInfo != nullptr)
	{
		std::wcout << L"lpVendorInfo: " << ToWString(wsaData.lpVendorInfo) << std::endl;
	}
	else
	{
		std::wcout << L"lpVendorInfo: null" << std::endl;
	}
	if (wsaData.szDescription != nullptr)
	{
		std::wcout << L"szDescription: " << ToWString(wsaData.szDescription) << std::endl;
	}
	else
	{
		std::wcout << L"szDescription: null" << std::endl;
	}
	if (wsaData.szSystemStatus != nullptr)
	{
		std::wcout << L"szSystemStatus: " << ToWString(wsaData.szSystemStatus) << std::endl;
	}
	else
	{
		std::wcout << L"szSystemStatus: null" << std::endl;
	}*/
}

class Arg
{
private:
	wchar_t** _argv;
	int _argc;
	int _index;

public:
	Arg(int argc, wchar_t* argv[], int index = 0)
		: _argc(argc), _argv(argv), _index(index)
	{}

	bool HasNext() const
	{
		return _index < _argc;
	}

	wchar_t* Next()
	{
		return HasNext() ? _argv[_index++] : nullptr;
	}

	std::wstring NextAsString(const std::wstring& defaultValue = L"")
	{
		return HasNext() ? std::wstring(_argv[_index++]) : defaultValue;
	}

	int NextAsInt(int defaultValue = 0)
	{
		return HasNext() ? _wtoi(_argv[_index++]) : defaultValue;
	}

	int RemainingArgCount() const
	{
		return _argc - _index;
	}

	wchar_t** RemainingArgs() const
	{
		return &_argv[_index];
	}

	Arg Remaining()
	{
		return Arg(_argc - _index, &_argv[_index], 0);
	}
};

typedef struct _SendWorkItem {
	SOCKET socket;
	WSABUF buffer;
	WSAOVERLAPPED overlapped;
	DWORD totalTransferred;
	std::vector<char> payload;
} SendWorkItem, * PSendWorkItem;

typedef struct _RecvWorkItem {
	SOCKET socket;
	WSABUF buffer;
	WSAOVERLAPPED overlapped;
	DWORD totalTransferred;
	std::vector<char> payload;
} RecvWorkItem, * PRecvWorkItem;

void SendWorkItemCallback(
	DWORD dwError,
	DWORD cbTransferred,
	LPWSAOVERLAPPED lpOverlapped,
	DWORD dwFlags)
{
	BEGIN_FUNCTION;

	TRACE_FUNCTION << L"dwError = " << dwError << L", cbTransferred = " << cbTransferred << std::endl;

	PSendWorkItem pwi = CONTAINING_RECORD(lpOverlapped, SendWorkItem, overlapped);
	DWORD payloadSize = (DWORD)pwi->payload.size();
	pwi->totalTransferred += cbTransferred;

	if (dwError == 0 && pwi->totalTransferred < payloadSize)
	{
		pwi->buffer.buf = &pwi->payload.data()[pwi->totalTransferred];
		pwi->buffer.len = payloadSize - pwi->totalTransferred;

		dwError = WSASend(pwi->socket, &pwi->buffer, 1, nullptr, 0, &pwi->overlapped, SendWorkItemCallback);

		if (dwError == SOCKET_ERROR)
		{
			dwError = WSAGetLastError();
		}

		TRACE_FUNCTION << L"WSASend returns " << dwError << std::endl;
	}

	if (dwError == WSA_IO_PENDING)
	{
		TRACE_FUNCTION << L"WSASend is pending with result " << dwError << std::endl;
	}
	else if (dwError != 0)
	{
		TRACE_FUNCTION << L"WSASend failed with error " << dwError << std::endl;
	}
	else if (pwi->totalTransferred < payloadSize)
	{
		TRACE_FUNCTION << L"WSASend succeeded with result " << dwError << std::endl;
	}
	else if (pwi->totalTransferred == payloadSize)
	{
		TRACE_FUNCTION << L"WSASend competed the payload with result " << dwError << std::endl;
	}

	if ((dwError == 0 && pwi->totalTransferred == payloadSize) || (dwError != 0 && dwError != WSA_IO_PENDING))
	{
		if (!WSASetEvent(pwi->overlapped.hEvent))
		{
			dwError = WSAGetLastError();
			TRACE_FUNCTION << L"WSASetEvent failed with error " << dwError << std::endl;
		}
	}

	END_FUNCTION;
}

void RecvWorkItemCallback(
	DWORD dwError,
	DWORD cbTransferred,
	LPWSAOVERLAPPED lpOverlapped,
	DWORD dwFlags)
{
	BEGIN_FUNCTION;

	TRACE_FUNCTION << L"dwError = " << dwError << L", cbTransferred = " << cbTransferred << std::endl;

	PRecvWorkItem pwi = CONTAINING_RECORD(lpOverlapped, RecvWorkItem, overlapped);
	pwi->totalTransferred += cbTransferred;
	DWORD sizeofDWORD = sizeof(DWORD);

	if (dwError == 0)
	{
		if (pwi->totalTransferred == 0)
		{
			//pwi->payload.resize(2048);
			pwi->payload.resize(sizeofDWORD);
			TRACE_FUNCTION << L"payload resized " << pwi->payload.size() << std::endl;
		}
		//else if (pwi->totalTransferred >= sizeofDWORD)
		else if (pwi->totalTransferred == sizeofDWORD)
		{
			DWORD expectTransfferred = *((PDWORD)pwi->payload.data());
			pwi->payload.resize(expectTransfferred + sizeofDWORD);
			*((PDWORD)pwi->payload.data()) = expectTransfferred;
			TRACE_FUNCTION << L"payload resized " << pwi->payload.size() << std::endl;
		}

		TRACE_FUNCTION << L"totalTransferred " << pwi->totalTransferred << L", payload size " << pwi->payload.size() << std::endl;
		if (pwi->totalTransferred < pwi->payload.size())
		{
			pwi->buffer.buf = &pwi->payload.data()[pwi->totalTransferred];
			pwi->buffer.len = (DWORD)pwi->payload.size() - pwi->totalTransferred;

			TRACE_FUNCTION << L"buf 0x" << std::hex << (byte*)pwi->buffer.buf << std::dec << L", len " << pwi->buffer.len << std::endl;

			//
			// dwFlags must be provided, otherwise WSARecv fails with WSAEFAULT
			//

			dwError = WSARecv(pwi->socket, &pwi->buffer, 1, nullptr, &dwFlags, &pwi->overlapped, RecvWorkItemCallback);

			if (dwError == SOCKET_ERROR)
			{
				dwError = WSAGetLastError();
			}

			TRACE_FUNCTION << L"WSARecv returns " << dwError << std::endl;
		}
	}

	if (dwError == WSA_IO_PENDING)
	{
		TRACE_FUNCTION << L"WSARecv is pending with result " << dwError << std::endl;
	}
	else if (dwError != 0)
	{
		TRACE_FUNCTION << L"WSARecv failed with error " << dwError << std::endl;
	}
	else if (pwi->totalTransferred < pwi->payload.size())
	{
		TRACE_FUNCTION << L"WSARecv succeeded with result " << dwError << std::endl;
	}
	else if (pwi->totalTransferred == pwi->payload.size())
	{
		TRACE_FUNCTION << L"WSARecv competed the payload with result " << dwError << std::endl;
	}

	if ((dwError == 0 && pwi->totalTransferred == pwi->payload.size()) || (dwError != 0 && dwError != WSA_IO_PENDING))
	{
		if (!WSASetEvent(pwi->overlapped.hEvent))
		{
			dwError = WSAGetLastError();
			TRACE_FUNCTION << L"WSASetEvent failed with error " << dwError << std::endl;
		}
	}

	END_FUNCTION;
}

DWORD Server(Arg& arg)
{
	DWORD error = ERROR_SUCCESS;
	sockaddr_in clientAddr{ 0 };
	int clientAddrSize = sizeof(clientAddr);
	SOCKET clientSocket = INVALID_SOCKET;
	sockaddr_in serverAddr{ 0 };
	SOCKET serverSocket = INVALID_SOCKET;
	RecvWorkItem wi{ 0 };
	DWORD sizeofDWORD = sizeof(DWORD);
	DWORD payloadSize = 0;
	DWORD flags = 0;

	if (arg.RemainingArgCount() < 2)
	{
		return ERROR_BAD_ARGUMENTS;
	}

	std::wstring serverIp = arg.NextAsString();
	u_short serverPort = (u_short)arg.NextAsInt();

	serverSocket = WSASocketW(
		AF_INET,
		SOCK_STREAM,
		IPPROTO_TCP,
		nullptr,
		0,
		WSA_FLAG_OVERLAPPED);

	if (serverSocket == INVALID_SOCKET)
	{
		error = WSAGetLastError();
		std::wcerr << L"WSASocket failed with error " << error << std::endl;
		goto finally;
	}

	std::wcout << L"Server socket = 0x" << std::hex << serverSocket << std::dec << std::endl;

	error = GetSockAddrIn(serverIp, serverPort, serverAddr);
	if (error != ERROR_SUCCESS)
	{
		std::wcerr << L"GetSockAddrIn(" << serverIp << L", " << serverPort << ") failed with error " << error << std::endl;
		goto finally;
	}

	error = bind(serverSocket, (const sockaddr*)&serverAddr, sizeof(serverAddr));
	if (error == SOCKET_ERROR)
	{
		error = WSAGetLastError();
		std::wcerr << L"bind failed with error " << error << std::endl;
		goto finally;
	}

	std::wcout << L"bind succeeded with result " << error << std::endl;

	error = listen(serverSocket, SOMAXCONN);
	if (error == SOCKET_ERROR)
	{
		error = WSAGetLastError();
		std::wcerr << L"listen failed with error " << error << std::endl;
		goto finally;
	}

	std::wcout << L"listen succeeded with result " << error << std::endl;

	clientSocket = WSAAccept(serverSocket, (sockaddr*)&clientAddr, &clientAddrSize, nullptr, 0);
	if (clientSocket == INVALID_SOCKET)
	{
		error = WSAGetLastError();
		std::wcerr << L"WSAAccept failed with error " << error << std::endl;
		goto finally;
	}

	std::wcout << L"WSAAccept succeeded, client socket = 0x" << std::hex << clientSocket << std::dec << std::endl;
	std::wcout << L"client sockaddr_in.[sin_family|sin_addr|sin_port] = [" << clientAddr.sin_family << L"|0x" << std::hex << clientAddr.sin_addr.s_addr << L"|0x" << clientAddr.sin_port << std::dec << L"]" << std::endl;

	wi.socket = clientSocket;
	wi.totalTransferred = 0;

	wi.overlapped.hEvent = WSACreateEvent();

	if (wi.overlapped.hEvent == WSA_INVALID_EVENT) {
		error = WSAGetLastError();
		std::wcerr << L"WSACreateEvent failed with error " << error << std::endl;
		goto finally;
	}

	RecvWorkItemCallback(0, 0, &wi.overlapped, flags);

	error = WSAWaitForMultipleEvents(1, &wi.overlapped.hEvent, TRUE, INFINITE, TRUE);
	if (error == WSA_WAIT_FAILED) {
		error = WSAGetLastError();
		std::wcerr << L"WSAWaitForMultipleEvents failed with error " << error << std::endl;
	}

	if (wi.overlapped.hEvent != WSA_INVALID_EVENT)
	{
		if (!WSACloseEvent(wi.overlapped.hEvent))
		{
			error = WSAGetLastError();
			std::wcerr << L"WSACloseEvent failed with error " << error << std::endl;
		}
		else
		{
			wi.overlapped.hEvent = WSA_INVALID_EVENT;
		}
	}

	std::wcerr << L"Received bytes: " << wi.payload.size() << std::endl;

	if (wi.payload.size() >= sizeofDWORD)
	{
		payloadSize = *((PWORD)wi.payload.data());

		for (DWORD i = 0; i < payloadSize; i++)
		{
			if (wi.payload[sizeofDWORD + i] != (char)i)
			{
				std::wcerr << L"payload[" << (sizeofDWORD + i) << L"!=" << ((char)i) << L" " << std::endl;
			}
		}
	}

	finally:

	if (clientSocket != INVALID_SOCKET)
	{
		error = shutdown(clientSocket, SD_BOTH);
		if (error == SOCKET_ERROR)
		{
			error = WSAGetLastError();
			std::wcerr << L"shutdown(0x" << std::hex << clientSocket << std::dec << L") failed with error " << error << std::endl;
		}
		else
		{
			std::wcout << L"shutdown(0x" << std::hex << clientSocket << std::dec << L") succeeded with result " << error << std::endl;
		}

		error = closesocket(clientSocket);
		if (error == SOCKET_ERROR)
		{
			error = WSAGetLastError();
			std::wcerr << L"closesocket(0x" << std::hex << clientSocket << std::dec << L") failed with error " << error << std::endl;
		}
		else
		{
			std::wcout << L"closesocket(0x" << std::hex << clientSocket << std::dec << L") succeeded with result " << error << std::endl;
			clientSocket = INVALID_SOCKET;
		}
	}

	if (serverSocket != INVALID_SOCKET)
	{
		error = shutdown(serverSocket, SD_BOTH);
		if (error == SOCKET_ERROR)
		{
			error = WSAGetLastError();
			std::wcerr << L"shutdown(0x" << std::hex << serverSocket << std::dec << L") failed with error " << error << std::endl;
		}
		else
		{
			std::wcout << L"shutdown(0x" << std::hex << serverSocket << std::dec << L") succeeded with result " << error << std::endl;
		}

		error = closesocket(serverSocket);
		if (error == SOCKET_ERROR)
		{
			error = WSAGetLastError();
			std::wcerr << L"closesocket(0x" << std::hex << serverSocket << std::dec << L") failed with error " << error << std::endl;
		}
		else
		{
			std::wcout << L"closesocket(0x" << std::hex << serverSocket << std::dec << L") succeeded with result " << error << std::endl;
			serverSocket = INVALID_SOCKET;
		}
	}

	return ERROR_SUCCESS;
}

DWORD Client(Arg& arg)
{
	DWORD error = ERROR_SUCCESS;
	sockaddr_in addr{ 0 };
	SOCKET socket = INVALID_SOCKET;
	SendWorkItem wi{ 0 };
	DWORD payloadSize = 1024;
	DWORD sizeofDWORD = sizeof(DWORD);

	if (arg.RemainingArgCount() < 2)
	{
		return ERROR_BAD_ARGUMENTS;
	}

	std::wstring ip = arg.NextAsString();
	u_short port = (u_short)arg.NextAsInt();

	socket = WSASocketW(
		AF_INET,
		SOCK_STREAM,
		IPPROTO_TCP,
		nullptr,
		0,
		WSA_FLAG_OVERLAPPED);

	if (socket == INVALID_SOCKET)
	{
		error = WSAGetLastError();
		std::wcerr << L"WSASocket failed with error " << error << std::endl;
		goto finally;
	}

	std::wcout << L"socket = 0x" << std::hex << socket << std::dec << std::endl;

	error = GetSockAddrIn(ip, port, addr);
	if (error != ERROR_SUCCESS)
	{
		std::wcerr << L"GetSockAddrIn(" << ip << L", " << port << ") failed with error " << error << std::endl;
		goto finally;
	}

	error = WSAConnect(socket, (const sockaddr*)&addr, sizeof(addr), nullptr, nullptr, nullptr, nullptr);
	if (error == SOCKET_ERROR)
	{
		error = WSAGetLastError();
		std::wcerr << L"WSAConnect failed with error " << error << std::endl;
		goto finally;
	}

	std::wcout << L"WSAConnect succeeded with result " << error << std::endl;

	wi.socket = socket;
	wi.payload.resize(payloadSize + sizeofDWORD);
	*((PDWORD)wi.payload.data()) = payloadSize;
	for (DWORD i = 0; i < payloadSize; i++)
	{
		wi.payload[sizeofDWORD + i] = (char)i;
	}

	wi.buffer.buf = (char*)wi.payload.data();
	wi.buffer.len = (ULONG)wi.payload.size();
	wi.totalTransferred = 0;

	wi.overlapped.hEvent = WSACreateEvent();

	if (wi.overlapped.hEvent == WSA_INVALID_EVENT)
	{
		error = WSAGetLastError();
		std::wcerr << L"WSACreateEvent failed with error " << error << std::endl;
		goto finally;
	}

	SendWorkItemCallback(0, 0, &wi.overlapped, 0);

	error = WSAWaitForMultipleEvents(1, &wi.overlapped.hEvent, TRUE, INFINITE, TRUE);
	if (error == WSA_WAIT_FAILED)
	{
		error = WSAGetLastError();
		std::wcerr << L"WSAWaitForMultipleEvents failed with error " << error << std::endl;
	}

	if (wi.overlapped.hEvent != WSA_INVALID_EVENT)
	{
		if (!WSACloseEvent(wi.overlapped.hEvent))
		{
			error = WSAGetLastError();
			std::wcerr << L"WSACloseEvent failed with error " << error << std::endl;
		}
		else
		{
			wi.overlapped.hEvent = WSA_INVALID_EVENT;
		}
	}

finally:

	if (socket != INVALID_SOCKET)
	{
		error = shutdown(socket, SD_BOTH);
		if (error == SOCKET_ERROR)
		{
			error = WSAGetLastError();
			std::wcerr << L"shutdown(0x" << std::hex << socket << std::dec << L") failed with error " << error << std::endl;
		}
		else
		{
			std::wcout << L"shutdown(0x" << std::hex << socket << std::dec << L") succeeded with result " << error << std::endl;
		}

		error = closesocket(socket);
		if (error == SOCKET_ERROR)
		{
			error = WSAGetLastError();
			std::wcerr << L"closesocket(0x" << std::hex << socket << std::dec << L") failed with error " << error << std::endl;
		}
		else
		{
			std::wcout << L"closesocket(0x" << std::hex << socket << std::dec << L") succeeded with result " << error << std::endl;
			socket = INVALID_SOCKET;
		}
	}

	return ERROR_SUCCESS;
}

std::wstring ToString(const GUID& guid)
{
	std::wostringstream oss;

	oss << std::hex << std::setfill(L'0') << std::setw(8) << std::uppercase << guid.Data1
		<< L"-" << std::setw(4) << std::uppercase << guid.Data2
		<< L"-" << std::setw(4) << std::uppercase << guid.Data3;
	for (int i = 0; i < 8; i++)
	{
		if (i == 0 || i == 2)
		{
			oss << L"-";
		}

		oss  << std::setw(2) << std::uppercase << guid.Data4[i];
	}

	return oss.str();
}

DWORD Print(const WSAPROTOCOL_INFOW& info)
{
	std::wcout << L"ServiceFlags1: 0x" << std::hex << info.dwServiceFlags1 << std::dec;

#define FLAG(x) \
	if (info.dwServiceFlags1 & x) \
	{ \
		std::wcout << L"|" << L#x; \
	}

	FLAG(XP1_CONNECTIONLESS);
	FLAG(XP1_GUARANTEED_DELIVERY);
	FLAG(XP1_GUARANTEED_ORDER);
	FLAG(XP1_MESSAGE_ORIENTED);
	FLAG(XP1_PSEUDO_STREAM);
	FLAG(XP1_GRACEFUL_CLOSE);
	FLAG(XP1_EXPEDITED_DATA);
	FLAG(XP1_CONNECT_DATA);
	FLAG(XP1_DISCONNECT_DATA);
	FLAG(XP1_SUPPORT_BROADCAST);
	FLAG(XP1_SUPPORT_MULTIPOINT);
	FLAG(XP1_MULTIPOINT_CONTROL_PLANE);
	FLAG(XP1_MULTIPOINT_DATA_PLANE);
	FLAG(XP1_QOS_SUPPORTED);
	FLAG(XP1_INTERRUPT);
	FLAG(XP1_UNI_SEND);
	FLAG(XP1_UNI_RECV);
	FLAG(XP1_IFS_HANDLES);
	FLAG(XP1_PARTIAL_MESSAGE);
	FLAG(XP1_SAN_SUPPORT_SDP);

#undef FLAG

	std::wcout << std::endl;

	std::wcout << L"ServiceFlags[2|3|4]: [0x" << std::hex << info.dwServiceFlags2 << L"|0x" << info.dwServiceFlags3 << L"|0x" << info.dwServiceFlags4 << L"]" << std::dec << std::endl;

	std::wcout << L"ProviderFlags1: 0x" << std::hex << info.dwProviderFlags << std::dec;

#define FLAG(x) \
	if (info.dwProviderFlags & x) \
	{ \
		std::wcout << L"|" << L#x; \
	}

	FLAG(PFL_MULTIPLE_PROTO_ENTRIES);
	FLAG(PFL_RECOMMENDED_PROTO_ENTRY);
	FLAG(PFL_HIDDEN);
	FLAG(PFL_MATCHES_PROTOCOL_ZERO);
	FLAG(PFL_NETWORKDIRECT_PROVIDER);

#undef FLAG

	std::wcout << std::endl;

	std::wcout << L"ProviderId: " << ToString(info.ProviderId) << std::endl;
	std::wcout << L"CatalogEntryId:" << info.dwCatalogEntryId << std::endl;

	std::wcout << L"ProtocolChain: " << info.ProtocolChain.ChainLen << L"|";

	for (int i = 0; i < info.ProtocolChain.ChainLen; i++)
	{
		if (i > 0)
		{
			std::wcout << L",";
		}

		std::wcout << info.ProtocolChain.ChainEntries[i];
	}

	std::wcout << std::endl;

	std::wcout << L"Version: " << info.iVersion << std::endl;

	std::wcout << L"AddressFamily: " << info.iAddressFamily;

#define ENUM(x) \
	if (info.iAddressFamily == (x)) \
	{ \
		std::wcout << L"|" << L#x; \
	}

	ENUM(AF_UNSPEC);
	ENUM(AF_UNIX);
	ENUM(AF_INET);
	ENUM(AF_IMPLINK);
	ENUM(AF_PUP);
	ENUM(AF_CHAOS);
	ENUM(AF_NS);
	ENUM(AF_IPX);
	ENUM(AF_ISO);
	ENUM(AF_OSI);
	ENUM(AF_ECMA);
	ENUM(AF_DATAKIT);
	ENUM(AF_CCITT);
	ENUM(AF_SNA);
	ENUM(AF_DECnet);
	ENUM(AF_DLI);
	ENUM(AF_LAT);
	ENUM(AF_HYLINK);
	ENUM(AF_APPLETALK);
	ENUM(AF_NETBIOS);
	ENUM(AF_VOICEVIEW);
	ENUM(AF_FIREFOX);
	ENUM(AF_UNKNOWN1);
	ENUM(AF_BAN);
	ENUM(AF_ATM);
	ENUM(AF_INET6);
	ENUM(AF_CLUSTER);
	ENUM(AF_12844);
	ENUM(AF_IRDA);
	ENUM(AF_NETDES);
	ENUM(AF_TCNPROCESS);
	ENUM(AF_TCNMESSAGE);
	ENUM(AF_ICLFXBM);
	ENUM(AF_BTH);
	ENUM(AF_LINK);
	ENUM(AF_HYPERV);
	ENUM(AF_MAX);

#undef ENUM

	std::wcout << std::endl;

	std::wcout << L"SockAddr[Max|Min]: [" << info.iMaxSockAddr << L"|" << info.iMinSockAddr << L"]" << std::endl;

	std::wcout << L"SocketType: " << info.iSocketType;

#define ENUM(x) \
	if (info.iSocketType == (x)) \
	{ \
		std::wcout << L"|" << L#x; \
	}

	ENUM(SOCK_STREAM);
	ENUM(SOCK_DGRAM);
	ENUM(SOCK_RAW);
	ENUM(SOCK_RDM);
	ENUM(SOCK_SEQPACKET);

#undef ENUM

	std::wcout << std::endl;

	std::wcout << L"Protocol: " << info.iProtocol;

#define ENUM(x) \
	if (info.iProtocol == (x)) \
	{ \
		std::wcout << L"|" << L#x; \
	}

	ENUM(IPPROTO_HOPOPTS);
	ENUM(IPPROTO_ICMP);
	ENUM(IPPROTO_IGMP);
	ENUM(IPPROTO_GGP);
	ENUM(IPPROTO_IPV4);
	ENUM(IPPROTO_ST);
	ENUM(IPPROTO_TCP);
	ENUM(IPPROTO_CBT);
	ENUM(IPPROTO_EGP);
	ENUM(IPPROTO_IGP);
	ENUM(IPPROTO_PUP);
	ENUM(IPPROTO_UDP);
	ENUM(IPPROTO_IDP);
	ENUM(IPPROTO_RDP);
	ENUM(IPPROTO_IPV6);
	ENUM(IPPROTO_ROUTING);
	ENUM(IPPROTO_FRAGMENT);
	ENUM(IPPROTO_ESP);
	ENUM(IPPROTO_AH);
	ENUM(IPPROTO_ICMPV6);
	ENUM(IPPROTO_NONE);
	ENUM(IPPROTO_DSTOPTS);
	ENUM(IPPROTO_ND);
	ENUM(IPPROTO_ICLFXBM);
	ENUM(IPPROTO_PIM);
	ENUM(IPPROTO_PGM);
	ENUM(IPPROTO_L2TP);
	ENUM(IPPROTO_SCTP);
	ENUM(IPPROTO_RAW);
	ENUM(IPPROTO_MAX);
	ENUM(IPPROTO_RESERVED_RAW);
	ENUM(IPPROTO_RESERVED_IPSEC);
	ENUM(IPPROTO_RESERVED_IPSECOFFLOAD);
	ENUM(IPPROTO_RESERVED_WNV);
	ENUM(IPPROTO_RESERVED_MAX);

#undef ENUM

	std::wcout << std::endl;

	std::wcout << L"ProtocolMaxOffset: " << info.iProtocolMaxOffset << std::endl;

	std::wcout << L"NetworkByteOrder: " << info.iNetworkByteOrder;

#define ENUM(x) \
	if (info.iNetworkByteOrder == (x)) \
	{ \
		std::wcout << L"|" << L#x; \
	}

	ENUM(BIGENDIAN);
	ENUM(LITTLEENDIAN);

#undef ENUM

	std::wcout << std::endl;

	std::wcout << L"SecurityScheme: " << info.iSecurityScheme << std::endl;
	std::wcout << L"MessageSize: " << info.dwMessageSize << std::endl;
	std::wcout << L"ProviderReserved: " << info.dwProviderReserved << std::endl;
	std::wcout << L"ProtocolDescription: " << info.szProtocol << std::endl;

	return ERROR_SUCCESS;
}

/// <summary>
/// The protocol information can be shown using command:
/// netsh winsock show catalog
/// </summary>
DWORD EnumProtocols(bool includeHidden = false)
{
	DWORD error = ERROR_SUCCESS;
	std::vector<byte> buffer;
	DWORD bufferLength = static_cast<DWORD>(buffer.size());
	LPWSAPROTOCOL_INFOW info = (LPWSAPROTOCOL_INFOW)buffer.data();
	int protocolCount = 0;

	if (includeHidden)
	{
		protocolCount = WSCEnumProtocols(
			nullptr /* lpiProtocols */,
			info,
			&bufferLength,
			(LPINT)&error);
		if (protocolCount == SOCKET_ERROR)
		{
			if (error == WSAENOBUFS)
			{
				buffer.resize(bufferLength);
				// update pointer since buffer is changed
				info = (LPWSAPROTOCOL_INFOW)buffer.data();
				protocolCount = WSCEnumProtocols(
					nullptr /* lpiProtocols */,
					info,
					&bufferLength,
					(LPINT)&error);
				if (protocolCount == SOCKET_ERROR)
				{
					return error;
				}
			}
			else
			{
				return error;
			}
		}
	}
	else
	{
		protocolCount = WSAEnumProtocolsW(
			nullptr /* lpiPrototols */,
			info,
			&bufferLength);
		if (protocolCount == SOCKET_ERROR)
		{
			error = WSAGetLastError();
			if (error == WSAENOBUFS)
			{
				buffer.resize(bufferLength);
				// update pointer since buffer is changed
				info = (LPWSAPROTOCOL_INFOW)buffer.data();
				protocolCount = WSAEnumProtocolsW(
					nullptr /* lpiPrototols */,
					info,
					&bufferLength);
				if (protocolCount == SOCKET_ERROR)
				{
					error = WSAGetLastError();
					return error;
				}
			}
			else
			{
				return error;
			}
		}
	}

	std::wcout << L"Found " << protocolCount << L" protocols." << std::endl;
	for (int i = 0; i < protocolCount; i++)
	{
		std::wcout << L"==== Protocol " << i << std::endl;
		Print(info[i]);
	}

	return ERROR_SUCCESS;
}

DWORD Print(const WSANAMESPACE_INFOEXW& info)
{
	std::wcout << L"ProviderId: " << ToString(info.NSProviderId) << std::endl;

	std::wcout << L"NameSpace: " << info.dwNameSpace;

#define ENUM(x) \
	if (info.dwNameSpace == (x)) \
	{ \
		std::wcout << L"|" << L#x; \
	}

	ENUM(NS_ALL);
	ENUM(NS_SAP);
	ENUM(NS_NDS);
	ENUM(NS_PEER_BROWSE);
	ENUM(NS_SLP);
	ENUM(NS_DHCP);
	ENUM(NS_TCPIP_LOCAL);
	ENUM(NS_TCPIP_HOSTS);
	ENUM(NS_DNS);
	ENUM(NS_NETBT);
	ENUM(NS_WINS);
	ENUM(NS_NLA);
	ENUM(NS_BTH);
	ENUM(NS_LOCALNAME);
	ENUM(NS_NBP);
	ENUM(NS_MS);
	ENUM(NS_STDA);
	ENUM(NS_NTDS);
	ENUM(NS_EMAIL);
	ENUM(NS_PNRPNAME);
	ENUM(NS_PNRPCLOUD);
	ENUM(NS_X500);
	ENUM(NS_NIS);
	ENUM(NS_NISPLUS);
	ENUM(NS_WRQ);
	ENUM(NS_NETDES);

#undef ENUM

	std::wcout << std::endl;

	std::wcout << L"Active: " << info.fActive << std::endl;
	std::wcout << L"Version: " << info.dwVersion << std::endl;
	std::wcout << L"Identifier: " << info.lpszIdentifier << std::endl;

	std::wcout << L"ProviderSpecific: " << info.ProviderSpecific.cbSize << std::endl;

	if (info.ProviderSpecific.cbSize > 0 && info.ProviderSpecific.pBlobData != nullptr)
	{
		NAPI_PROVIDER_INSTALLATION_BLOB* blob = (NAPI_PROVIDER_INSTALLATION_BLOB *)info.ProviderSpecific.pBlobData;

		std::wcout << L"  Version: " << blob->dwVersion << std::endl;
		std::wcout << L"  ProviderType: " << blob->dwProviderType;

#define ENUM(x) \
	if (blob->dwProviderType == (x)) \
	{ \
		std::wcout << L"|" << L#x; \
	}

		ENUM(ProviderType_Application);
		ENUM(ProviderType_Service);

#undef ENUM

		std::wcout << std::endl;

		std::wcout << L"  SupportsWildCard: " << blob->fSupportsWildCard << std::endl;

		std::wcout << L"  Domains: " << blob->cDomains << std::endl;
	}

	return ERROR_SUCCESS;
}

/// <summary>
/// The protocol information can be shown using command:
/// netsh winsock show catalog
/// </summary>
DWORD EnumNameSpaceProviders()
{
	DWORD error = ERROR_SUCCESS;
	std::vector<byte> buffer;
	DWORD bufferLength = 0;
	int providerCount = 0;
	LPWSANAMESPACE_INFOEXW info = nullptr;

	providerCount = WSAEnumNameSpaceProvidersExW(
		&bufferLength,
		nullptr);

	if (providerCount != SOCKET_ERROR)
	{
		std::wcerr << L"WSAEnumNameSpaceProvidersExW failed unexpectedly" << std::endl;
		return ERROR_BAD_ARGUMENTS;
	}

	error = WSAGetLastError();

	if (error != WSAEFAULT)
	{
		std::wcerr << L"WSAEnumNameSpaceProvidersExW failed with error " << error << std::endl;
		return error;
	}

	buffer.resize(bufferLength);

	providerCount = WSAEnumNameSpaceProvidersExW(
		&bufferLength,
		(LPWSANAMESPACE_INFOEXW)buffer.data());

	if (providerCount == SOCKET_ERROR)
	{
		error = WSAGetLastError();
		std::wcerr << L"WSAEnumNameSpaceProvidersExW failed with error " << error << std::endl;
		return error;
	}

	std::wcout << L"Found " << providerCount << L" namespace providers" << std::endl;

	info = (LPWSANAMESPACE_INFOEXW)buffer.data();

	for (int i = 0; i < providerCount; i++)
	{
		std::wcout << L"==== NameSpace Provider " << i << std::endl;
		Print(info[i]);
	}

	return ERROR_SUCCESS;
}

void Usage(int argc, wchar_t* argv[])
{
	std::wcout << L"Usage:" << std::endl;
	std::wcout << argv[0] << L" server <ip> <port>" << std::endl;
	std::wcout << argv[0] << L" client <ip> <port>" << std::endl;
	std::wcout << argv[0] << L" enumprotocols --include-hidden" << std::endl;
	std::wcout << argv[0] << L" enumnamespaceproviders" << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
	DWORD error = ERROR_SUCCESS;
	WSADATA wsaData;
	Arg arg(argc, argv, 1);
	std::wstring context;

	if (!arg.HasNext())
	{
		Usage(argc, argv);
		return ERROR_BAD_ARGUMENTS;
	}

	error = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (error != 0)
	{
		std::wcerr << L"WSAStartup(2.2) failed with error " << error << std::endl;
		return error;
	}
	else
	{
		std::wcout << L"WSAStartup(2.2) succeeded" << std::endl;
	}

	Print(wsaData);

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		std::wcerr << L"Winsock version not supported" << std::endl;
		goto finally;
	}

	context = arg.NextAsString();

	if (context == L"server")
	{
		error = Server(arg);
		if (error != ERROR_SUCCESS)
		{
			std::wcerr << L"Server failed with error " << error << std::endl;
		}
	}
	else if (context == L"client")
	{
		error = Client(arg);
		if (error != ERROR_SUCCESS)
		{
			std::wcerr << L"Client failed with error " << error << std::endl;
		}
	}
	else if (context == L"enumprotocols")
	{
		bool includeHidden = (arg.HasNext() && (arg.NextAsString() == L"--include-hidden"));

		error = EnumProtocols(includeHidden);
		if (error != ERROR_SUCCESS)
		{
			std::wcerr << L"EnumProtocols failed with error " << error << std::endl;
		}
	}
	else if (context == L"enumnamespaceproviders")
	{
		error = EnumNameSpaceProviders();
		if (error != ERROR_SUCCESS)
		{
			std::wcerr << L"EnumNameSpaceProviders failed with error " << error << std::endl;
		}
	}
	else
	{
		std::wcerr << L"Unknown context '" << context << L"'" << std::endl;
		return ERROR_BAD_ARGUMENTS;
	}

	finally:

	error = WSACleanup();

	if (error == SOCKET_ERROR)
	{
		error = WSAGetLastError();
		std::wcerr << L"WSACleanup failed with error " << error << std::endl;
	}
	else
	{
		std::wcout << L"WSACleanup succeeded" << std::endl;
	}

	return error;
}