#include <crtdbg.h>

#ifdef _DEBUG

class LeakDetector
{
	int initialstreams;
	_CrtMemState state;
public:
	LeakDetector()
	{
		initialstreams = _flushall();
		_CrtMemCheckpoint(&state);
	}
	~LeakDetector()
	{
		if (int leakingstreams = _flushall() - initialstreams)
		{
			_RPT1(_CRT_WARN, "WARNING: Leaking %d streams!\n", leakingstreams);
		}
		_cexit();
		_CrtMemDumpAllObjectsSince(&state);
		ExitProcess(0);
	}
};

#else

#define LeakDetector typedef void

#endif
