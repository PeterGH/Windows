#include <Windows.h>
#include <iostream>

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

#define TRACE_FUNCTION std::wcout << __FUNCTION__ << std::endl;

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
public:
    Work() : IWork()
    {
        TRACE_FUNCTION;
    }
    virtual ~Work()
    {
        TRACE_FUNCTION
    }
    virtual void Execute() override
    {
        TRACE_FUNCTION;
        ::Sleep(1000);
        ::InterlockedIncrement64(&WorkCount);
    }
};

class ThreadPool
{
private:
    TP_CALLBACK_ENVIRON _callbackEnv;
    PTP_POOL _pool;
    PTP_CLEANUP_GROUP _cleanupGroup;

    void Dispose()
    {
        if (_cleanupGroup != nullptr)
        {
            CloseThreadpoolCleanupGroupMembers(_cleanupGroup, false, nullptr);
            CloseThreadpoolCleanupGroup(_cleanupGroup);
            _cleanupGroup = nullptr;
        }

        if (_pool != nullptr)
        {
            CloseThreadpool(_pool);
            _pool = nullptr;
        }

        DestroyThreadpoolEnvironment(&_callbackEnv);
    }

public:
    ThreadPool()
        : _callbackEnv{ 0 }, _pool(nullptr), _cleanupGroup(nullptr)
    {}

    ~ThreadPool()
    {
        Dispose();
    }

    DWORD Init()
    {
        DWORD error = ERROR_SUCCESS;

        _cleanupGroup = CreateThreadpoolCleanupGroup();

        if (_cleanupGroup == nullptr)
        {
            RETURN_FAILURE(GetLastError());
        }

        _pool = CreateThreadpool(nullptr);

        if (_pool == nullptr)
        {
            RETURN_FAILURE(GetLastError());
        }

        SetThreadpoolThreadMaximum(_pool, 16);

        if (!SetThreadpoolThreadMinimum(_pool, 4))
        {
            RETURN_FAILURE(GetLastError());
        }

        InitializeThreadpoolEnvironment(&_callbackEnv);

        SetThreadpoolCallbackCleanupGroup(&_callbackEnv, _cleanupGroup, nullptr);
        SetThreadpoolCallbackPool(&_callbackEnv, _pool);

        return error;
    }

    static void CALLBACK WorkCallback(
        PTP_CALLBACK_INSTANCE instance,
        PVOID context,
        PTP_WORK work
    )
    {
        TRACE_FUNCTION;
        std::wcout << L"Start work instance " << std::hex << instance << std::dec << std::endl;
        IWork* iwork = (IWork*)context;
        iwork->Execute();
        CloseThreadpoolWork(work);
    }

    DWORD Submit(IWork* iwork)
    {
        DWORD error = ERROR_SUCCESS;

        PTP_WORK work = CreateThreadpoolWork(WorkCallback, iwork, &_callbackEnv);

        if (work == nullptr)
        {
            RETURN_FAILURE(GetLastError());
        }

        SubmitThreadpoolWork(work);
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

    std::wstring NextAsString()
    {
        return HasNext() ? std::wstring(_argv[_index++]) : L"";
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

void Usage(int argc, wchar_t* argv[])
{
    std::wcout << L"Usage:" << std::endl;
    std::wcout << argv[0] << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
    DWORD error = ERROR_SUCCESS;
    Arg arg(argc, argv, 1);
    ThreadPool threadpool;
    error = threadpool.Init();
    RETURN_IF_FAILED(error);

    Work work[30];
    for (int i = 0; i < 30; i++)
    {
        threadpool.Submit(&work[i]);
    }

    while (WorkCount < 30)
    {
        std::wcout << L"Wait for all works to complete." << std::endl;
        ::Sleep(1000);
    }

    return error;
}