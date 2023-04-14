#include <Windows.h>
#include <iostream>
#include <sstream>

#define RETURN_IF_FAILED(e) \
    { \
        DWORD _e = (e); \
        if (_e != ERROR_SUCCESS) \
        { \
            std::wcerr << L"[ERROR] " << __FUNCTION__ << L" returns " << _e << L" at " << __FILE__ << L" line " << __LINE__ << std::endl; \
            return _e; \
        } \
    }

#define RETURN_FAILURE(e) \
    { \
        DWORD _e = (e); \
        std::wcerr << L"[ERROR] " << __FUNCTION__ << L" returns " << _e << L" at " << __FILE__ << L" line " << __LINE__ << std::endl; \
        return _e; \
    }

#define TRACE_FUNCTION std::wcout << L"[" << GetSystemTimeString() << L"] "<< __FUNCTION__ << std::endl;

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
        oss << st.wHour << L"-" << st.wMinute << L"-" << st.wSecond << L"-" << st.wMilliseconds;
        time.assign(oss.str());
    }

    return date + L" " + time;
}


class IWork
{
public:
    IWork()
    {
        TRACE_FUNCTION;
    };
    virtual ~IWork()
    {
        TRACE_FUNCTION;
    };
    virtual void Execute() = 0;
};

volatile static LONG64 WorkCount = 0;

class Work : public IWork
{
private:
    UINT64 _id;

public:
    Work(UINT64 id = 0) : IWork(), _id(id)
    {
        TRACE_FUNCTION;
    }
    virtual ~Work()
    {
        TRACE_FUNCTION
    }

    void SetId(UINT64 id)
    {
        _id = id;
    }

    virtual void Execute() override
    {
        TRACE_FUNCTION;
        std::wcout << L"[Begin] work " << _id << std::endl;
        ::Sleep(2000);
        ::InterlockedIncrement64(&WorkCount);
        std::wcout << L"[End] work " << _id << std::endl;
    }
};

class ThreadPool
{
protected:
    TP_CALLBACK_ENVIRON _callbackEnv;
    PTP_POOL _pool;
    PTP_CLEANUP_GROUP _cleanupGroup;

    void Dispose()
    {
        TRACE_FUNCTION;

        if (_cleanupGroup != nullptr)
        {
            ::CloseThreadpoolCleanupGroupMembers(_cleanupGroup, false, nullptr);
            ::CloseThreadpoolCleanupGroup(_cleanupGroup);
            _cleanupGroup = nullptr;
        }

        if (_pool != nullptr)
        {
            ::CloseThreadpool(_pool);
            _pool = nullptr;
        }

        ::DestroyThreadpoolEnvironment(&_callbackEnv);
    }

public:
    ThreadPool()
        : _callbackEnv{ 0 }, _pool(nullptr), _cleanupGroup(nullptr)
    {
        TRACE_FUNCTION;
    }

    virtual ~ThreadPool()
    {
        TRACE_FUNCTION;
        Dispose();
    }

    virtual DWORD Init()
    {
        TRACE_FUNCTION;

        DWORD error = ERROR_SUCCESS;

        _cleanupGroup = ::CreateThreadpoolCleanupGroup();

        if (_cleanupGroup == nullptr)
        {
            RETURN_FAILURE(GetLastError());
        }

        _pool = ::CreateThreadpool(nullptr);

        if (_pool == nullptr)
        {
            RETURN_FAILURE(GetLastError());
        }

        ::SetThreadpoolThreadMaximum(_pool, 16);

        if (!::SetThreadpoolThreadMinimum(_pool, 4))
        {
            RETURN_FAILURE(GetLastError());
        }

        ::InitializeThreadpoolEnvironment(&_callbackEnv);

        ::SetThreadpoolCallbackCleanupGroup(&_callbackEnv, _cleanupGroup, nullptr);
        ::SetThreadpoolCallbackPool(&_callbackEnv, _pool);

        return error;
    }

    virtual DWORD Submit(IWork* iwork)
    {
        TRACE_FUNCTION;
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
};

class ThreadPool1 : public ThreadPool
{
public:
    static void CALLBACK WorkCallback(
        PTP_CALLBACK_INSTANCE instance,
        PVOID context,
        PTP_WORK work)
    {
        TRACE_FUNCTION;
        std::wcout << L"Start work instance " << std::hex << instance << std::dec << std::endl;
        IWork* iwork = (IWork*)context;
        iwork->Execute();
        ::CloseThreadpoolWork(work);
    }

    virtual DWORD Submit(IWork* iwork) override
    {
        TRACE_FUNCTION;

        DWORD error = ERROR_SUCCESS;

        PTP_WORK work = ::CreateThreadpoolWork(WorkCallback, iwork, &_callbackEnv);

        if (work == nullptr)
        {
            RETURN_FAILURE(GetLastError());
        }

        ::SubmitThreadpoolWork(work);
        return error;
    }
};

class ThreadPool2 : public ThreadPool
{
private:
    typedef struct _Item
    {
        SLIST_ENTRY Link;
        IWork* Work;
        ThreadPool2* ThreadPool;
    } Item, *PItem;

    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)
    SLIST_HEADER _head;

    PTP_WORK _work;
    volatile LONG64 _pendingCount;
    volatile LONG64 _runningCount;
    volatile LONG64 _completeCount;

public:

    ThreadPool2() : ThreadPool(), _head{ 0 }, _work(nullptr), _pendingCount(0), _runningCount(0), _completeCount(0)
    {
        TRACE_FUNCTION;
    }

    LONG64 PendingCount() { return _pendingCount; }
    LONG64 RunningCount() { return _runningCount; }
    LONG64 CompleteCount() { return _completeCount; }

    static void CALLBACK WorkCallback(
        PTP_CALLBACK_INSTANCE instance,
        PVOID context,
        PTP_WORK work)
    {
        TRACE_FUNCTION;

        std::wcout << L"Start work instance " << std::hex << instance << std::dec << std::endl;

        PSLIST_HEADER head = (PSLIST_HEADER)context;
        PSLIST_ENTRY entry = ::InterlockedPopEntrySList(head);

        if (entry == nullptr)
        {
            std::wcout << L"No pending work to do." << std::endl;
        }
        else
        {
            PItem item = (PItem)CONTAINING_RECORD(entry, Item, Link);
            ::InterlockedDecrement64(&item->ThreadPool->_pendingCount);
            ::InterlockedIncrement64(&item->ThreadPool->_runningCount);

            item->Work->Execute();

            ::InterlockedDecrement64(&item->ThreadPool->_runningCount);
            ::InterlockedIncrement64(&item->ThreadPool->_completeCount);
            _aligned_free(item);
            item = nullptr;
        }
    }

    virtual DWORD Init() override
    {
        TRACE_FUNCTION;

        DWORD error = ERROR_SUCCESS;

        error = ThreadPool::Init();
        RETURN_IF_FAILED(error);

        ::InitializeSListHead(&_head);

        _work = ::CreateThreadpoolWork(WorkCallback, &_head, &_callbackEnv);

        if (_work == nullptr)
        {
            RETURN_FAILURE(GetLastError());
        }

        return error;
    }

    virtual DWORD Submit(IWork* iwork) override
    {
        TRACE_FUNCTION;

        DWORD error = ERROR_SUCCESS;

        PItem item = (PItem)_aligned_malloc(sizeof(Item), MEMORY_ALLOCATION_ALIGNMENT);

        if (item == nullptr)
        {
            RETURN_FAILURE(ERROR_NOT_ENOUGH_MEMORY);
        }

        item->Work = iwork;
        item->ThreadPool = this;
        ::InterlockedPushEntrySList(&_head, &item->Link);
        ::InterlockedIncrement64(&_pendingCount);

        while (_runningCount > 2)
        {
            std::wcout << L"Waiting for running work count to drop." << std::endl;
            ::Sleep(200);
        }

        ::SubmitThreadpoolWork(_work);
        return error;
    }
};

class ThreadPool3 : public ThreadPool
{
public:
    static void CALLBACK TimerCallback(
        PTP_CALLBACK_INSTANCE instance,
        PVOID context,
        PTP_TIMER timer)
    {
        TRACE_FUNCTION;
        std::wcout << L"Start timer instance " << std::hex << instance << std::dec << std::endl;
        IWork* iwork = (IWork*)context;
        iwork->Execute();
        ::CloseThreadpoolTimer(timer);
    }

    virtual DWORD Submit(IWork* iwork) override
    {
        TRACE_FUNCTION;

        DWORD error = ERROR_SUCCESS;

        PTP_TIMER timer = ::CreateThreadpoolTimer(TimerCallback, iwork, &_callbackEnv);

        if (timer == nullptr)
        {
            RETURN_FAILURE(GetLastError());
        }

        ULARGE_INTEGER ul;
        ul.QuadPart = -(1000 * 1000 * 10); // 1 second
        FILETIME due = { ul.LowPart, ul.HighPart };
        ::SetThreadpoolTimer(timer, &due, 0, 0);
        return error;
    }
};

class ThreadPool4 : public ThreadPool
{
protected:
    typedef struct _Item
    {
        SLIST_ENTRY Link;
        IWork* Work;
        ThreadPool4* ThreadPool;
    } Item, * PItem;

    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)
    SLIST_HEADER _head;

    PTP_TIMER _timer;
    volatile LONG64 _pendingCount;
    volatile LONG64 _runningCount;
    volatile LONG64 _completeCount;
    bool _timerFired;

public:

    ThreadPool4() : ThreadPool(), _head{ 0 }, _timer(nullptr), _pendingCount(0), _runningCount(0), _completeCount(0), _timerFired(false)
    {
        TRACE_FUNCTION;
    }

    LONG64 PendingCount() { return _pendingCount; }
    LONG64 RunningCount() { return _runningCount; }
    LONG64 CompleteCount() { return _completeCount; }

    static void CALLBACK TimerCallback(
        PTP_CALLBACK_INSTANCE instance,
        PVOID context,
        PTP_TIMER timer)
    {
        TRACE_FUNCTION;

        std::wcout << L"Start work instance " << std::hex << instance << std::dec << std::endl;

        PSLIST_HEADER head = (PSLIST_HEADER)context;
        PSLIST_ENTRY entry = ::InterlockedPopEntrySList(head);

        if (entry == nullptr)
        {
            std::wcout << L"No pending work to do." << std::endl;
        }
        else
        {
            PItem item = (PItem)CONTAINING_RECORD(entry, Item, Link);
            ::InterlockedDecrement64(&item->ThreadPool->_pendingCount);
            ::InterlockedIncrement64(&item->ThreadPool->_runningCount);

            item->Work->Execute();

            ::InterlockedDecrement64(&item->ThreadPool->_runningCount);
            ::InterlockedIncrement64(&item->ThreadPool->_completeCount);
            _aligned_free(item);
            item = nullptr;
        }
    }

    virtual DWORD Init() override
    {
        TRACE_FUNCTION;

        DWORD error = ERROR_SUCCESS;

        error = ThreadPool::Init();
        RETURN_IF_FAILED(error);

        ::InitializeSListHead(&_head);

        _timer = ::CreateThreadpoolTimer(TimerCallback, &_head, &_callbackEnv);

        if (_timer == nullptr)
        {
            RETURN_FAILURE(GetLastError());
        }

        return error;
    }

    virtual DWORD Submit(IWork* iwork) override
    {
        TRACE_FUNCTION;

        DWORD error = ERROR_SUCCESS;

        PItem item = (PItem)_aligned_malloc(sizeof(Item), MEMORY_ALLOCATION_ALIGNMENT);

        if (item == nullptr)
        {
            RETURN_FAILURE(ERROR_NOT_ENOUGH_MEMORY);
        }

        item->Work = iwork;
        item->ThreadPool = this;
        ::InterlockedPushEntrySList(&_head, &item->Link);
        ::InterlockedIncrement64(&_pendingCount);

        if (!_timerFired)
        {
            ULARGE_INTEGER ul;
            ul.QuadPart = -(1000 * 1000 * 10); // 1 second
            FILETIME due = { ul.LowPart, ul.HighPart };
            // due in 1 second and repeat every second
            ::SetThreadpoolTimer(_timer, &due, 1000, 0);
            _timerFired = true;
        }

        return error;
    }
};

class ThreadPool5 : public ThreadPool
{
protected:
    typedef struct _Item
    {
        SLIST_ENTRY Link;
        IWork* Work;
        ThreadPool5* ThreadPool;
    } Item, * PItem;

    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)
        SLIST_HEADER _head;

    PTP_TIMER _timer;
    volatile LONG64 _pendingCount;
    volatile LONG64 _runningCount;
    volatile LONG64 _completeCount;
    bool _timerFired;

public:

    ThreadPool5() : ThreadPool(), _head{ 0 }, _timer(nullptr), _pendingCount(0), _runningCount(0), _completeCount(0), _timerFired(false)
    {
        TRACE_FUNCTION;
    }

    LONG64 PendingCount() { return _pendingCount; }
    LONG64 RunningCount() { return _runningCount; }
    LONG64 CompleteCount() { return _completeCount; }

    static void CALLBACK TimerCallback(
        PTP_CALLBACK_INSTANCE instance,
        PVOID context,
        PTP_TIMER timer)
    {
        TRACE_FUNCTION;

        std::wcout << L"Start work instance " << std::hex << instance << std::dec << std::endl;

        PSLIST_HEADER head = (PSLIST_HEADER)context;
        PSLIST_ENTRY entry = ::InterlockedPopEntrySList(head);

        if (entry == nullptr)
        {
            std::wcout << L"No pending work to do." << std::endl;
        }
        else
        {
            PItem item = (PItem)CONTAINING_RECORD(entry, Item, Link);
            ::InterlockedDecrement64(&item->ThreadPool->_pendingCount);
            ::InterlockedIncrement64(&item->ThreadPool->_runningCount);

            item->Work->Execute();

            ::InterlockedDecrement64(&item->ThreadPool->_runningCount);
            ::InterlockedIncrement64(&item->ThreadPool->_completeCount);
            _aligned_free(item);
            item = nullptr;

            ULARGE_INTEGER ul;
            ul.QuadPart = 0;
            FILETIME due = { ul.LowPart, ul.HighPart };
            ::SetThreadpoolTimer(timer, &due, 0, 0);
        }
    }

    virtual DWORD Init() override
    {
        TRACE_FUNCTION;

        DWORD error = ERROR_SUCCESS;

        error = ThreadPool::Init();
        RETURN_IF_FAILED(error);

        ::InitializeSListHead(&_head);

        _timer = ::CreateThreadpoolTimer(TimerCallback, &_head, &_callbackEnv);

        if (_timer == nullptr)
        {
            RETURN_FAILURE(GetLastError());
        }

        return error;
    }

    virtual DWORD Submit(IWork* iwork) override
    {
        TRACE_FUNCTION;

        DWORD error = ERROR_SUCCESS;

        PItem item = (PItem)_aligned_malloc(sizeof(Item), MEMORY_ALLOCATION_ALIGNMENT);

        if (item == nullptr)
        {
            RETURN_FAILURE(ERROR_NOT_ENOUGH_MEMORY);
        }

        item->Work = iwork;
        item->ThreadPool = this;
        ::InterlockedPushEntrySList(&_head, &item->Link);
        ::InterlockedIncrement64(&_pendingCount);

        if (!_timerFired)
        {
            ULARGE_INTEGER ul;
            ul.QuadPart = -(1000 * 1000 * 10); // 1 second
            FILETIME due = { ul.LowPart, ul.HighPart };
            ::SetThreadpoolTimer(_timer, &due, 0, 0);
            _timerFired = true;
        }

        return error;
    }
};

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

DWORD TestThread(ThreadPool& threadpool)
{
    DWORD error = ERROR_SUCCESS;

    error = threadpool.Init();
    RETURN_IF_FAILED(error);

    Work work[30];
    for (int i = 0; i < 30; i++)
    {
        work[i].SetId(i);
        threadpool.Submit(&work[i]);
    }

    while (WorkCount < 30)
    {
        std::wcout << L"Wait for all works to complete." << std::endl;
        ::Sleep(1000);
    }

    return error;
}

void Usage(int argc, wchar_t* argv[])
{
    std::wcout << L"Usage:" << std::endl;
    std::wcout << argv[0] << L" [1|2|3|4|5]" << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
    DWORD error = ERROR_SUCCESS;
    Arg arg(argc, argv, 1);

    if (arg.HasNext())
    {
        int choice = arg.NextAsInt();
        if (choice == 1)
        {
            ThreadPool1 threadpool;
            error = TestThread(threadpool);
        }
        else if (choice == 2)
        {
            ThreadPool2 threadpool;
            error = TestThread(threadpool);
            std::wcout << L"ThreadPool[Pending|Running|Complete]Count = ["
                << threadpool.PendingCount() << L"|" << threadpool.RunningCount() << L"|" << threadpool.CompleteCount() << L"]" << std::endl;
        }
        else if (choice == 3)
        {
            ThreadPool3 threadpool;
            error = TestThread(threadpool);
        }
        else if (choice == 4)
        {
            ThreadPool4 threadpool;
            error = TestThread(threadpool);
            std::wcout << L"ThreadPool[Pending|Running|Complete]Count = ["
                << threadpool.PendingCount() << L"|" << threadpool.RunningCount() << L"|" << threadpool.CompleteCount() << L"]" << std::endl;
        }
        else if (choice == 5)
        {
            ThreadPool5 threadpool;
            error = TestThread(threadpool);
            std::wcout << L"ThreadPool[Pending|Running|Complete]Count = ["
                << threadpool.PendingCount() << L"|" << threadpool.RunningCount() << L"|" << threadpool.CompleteCount() << L"]" << std::endl;
        }
    }
    else
    {
        Usage(argc, argv);
        return ERROR_BAD_ARGUMENTS;
    }

    return error;
}