#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <Shlobj.h>
#include <Strsafe.h>
#include <http.h>
#include <stdio.h>

static LPTSTR ServiceName = TEXT("RemoteShutdown");

DWORD SvcReportEvent(LPTSTR szFunction)
{
	HANDLE hEventSource = NULL;
	LPCTSTR lpszStrings[2] = { 0 };
	TCHAR Buffer[1024];
	TCHAR ErrorBuffer[512];
	DWORD error = NO_ERROR;

	hEventSource = RegisterEventSource(NULL, ServiceName);
	error = GetLastError();

	if (NULL != hEventSource)
	{
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), ErrorBuffer, sizeof ErrorBuffer / sizeof(ErrorBuffer[0]), NULL);
		CONST TCHAR* rwalk = szFunction;
		TCHAR* wwalk = Buffer;
		while (wwalk - Buffer < sizeof Buffer && *rwalk)
			*wwalk++ = *rwalk++;
		rwalk = TEXT(" failed with error: ");
		while (wwalk - Buffer < sizeof Buffer && *rwalk)
			*wwalk++ = *rwalk++;
		rwalk = ErrorBuffer;
		while (wwalk - Buffer < sizeof Buffer && *rwalk)
			*wwalk++ = *rwalk++;
		*wwalk++ = 0;


		lpszStrings[0] = ServiceName;
		lpszStrings[1] = Buffer;

		//goto Skip;
		ReportEvent(hEventSource,        // event log handle
			EVENTLOG_WARNING_TYPE, // event type
			0,                   // event category
			0,           // event identifier
			NULL,                // no security identifier
			2,                   // size of lpszStrings array
			0,                   // no binary data
			lpszStrings,         // array of strings
			NULL);               // no binary data
		DeregisterEventSource(hEventSource);
	}
	return error;
}

static void ShowError(LPCTSTR error) {
	MessageBox(NULL, error, TEXT("Error"), MB_OK | MB_ICONERROR);
}

static void ShowWindowsError(LPCTSTR title, const DWORD err) {
	TCHAR buff[1024];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), buff, sizeof buff / sizeof(buff[0]), NULL);
	MessageBox(NULL, buff, title, MB_OK | MB_ICONERROR);
}

#ifdef DEBUG
#pragma warning(push)
#pragma warning(disable:28251)
void* memcpy(void* dst, const void* src, size_t n)
{
	char* d = (char*)dst;
	const char* s = (const char*)src;
	for (size_t i = 0; i < n; i++)
		d[i] = s[i];
	return dst;
}

void* memset(void* dst, int c, size_t n)
{
	char* d = (char*)dst;
	for (size_t i = 0; i < n; i++)
		d[i] = c;
	return dst;
}

size_t strlen(const char* str)
{
	char* s = (char*)str;
	size_t n = 0;
	for (; *s; s++)
		n++;
	return n;
}

#pragma warning(pop)
#else
void* memcpy(void* dst, const void* src, size_t n)
{
	char* d = (char*)dst;
	const char* s = (const char*)src;
	for (size_t i = 0; i < n; i++)
		d[i] = s[i];
	return dst;
}

void* memset(void* dst, int c, size_t n)
{
	char* d = (char*)dst;
	for (size_t i = 0; i < n; i++)
		d[i] = c;
	return dst;
}

size_t strlen(const char* str)
{
	char* s = (char*)str;
	size_t n = 0;
	for (; *s; s++)
		n++;
	return n;
}
#endif

#pragma warning(push)
#pragma warning(disable:28159)
DWORD DoReceiveRequests(HANDLE hReqQueue) {
	for (;;) {
		char RequestBuffer[sizeof(HTTP_REQUEST) + 2048] = { 0 };
		PHTTP_REQUEST_V1 pRequest = (PHTTP_REQUEST_V1)RequestBuffer;
		ULONG result = HttpReceiveHttpRequest(hReqQueue, 0, 0, (PHTTP_REQUEST)pRequest, sizeof RequestBuffer, NULL, NULL);
		// Request queue was shutdown, just return.
		if (result == ERROR_OPERATION_ABORTED)
			return NO_ERROR;
		// Something else happened. TODO Log an event!
		if (result != NO_ERROR) {
			SvcReportEvent(TEXT("HttpReceiveHttpRequest"));
			return result;
		}

		if (pRequest->Verb != HttpVerbPOST) {
			HTTP_RESPONSE response = { 0 };
			LPCSTR reason = "Not implemented";
			response.StatusCode = 503;
			response.pReason = reason;
			response.ReasonLength = (USHORT)strlen(reason);
			result = HttpSendHttpResponse(hReqQueue, pRequest->RequestId, HTTP_SEND_RESPONSE_FLAG_DISCONNECT, &response, NULL, NULL, NULL, 0UL, NULL, NULL);
			if (result != NO_ERROR)
				ShowError(TEXT("Error sending HTTP response"));
			continue;
		}

		CHAR message[] = "Remote shutdown triggered";
		CHAR responseBuffer[255] = { 0 };
		BOOL ok = InitiateSystemShutdownExA(NULL, message, 3, TRUE, FALSE, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER);
		HTTP_RESPONSE response = { 0 };
		HTTP_DATA_CHUNK chunk = { 0 };
		response.EntityChunkCount = 1;
		response.pEntityChunks = &chunk;
		chunk.FromMemory.pBuffer = responseBuffer;
		if (!ok) {
			FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), responseBuffer, sizeof responseBuffer, NULL);
			response.StatusCode = 500;
			response.pReason = "Internal Server Error";
			response.ReasonLength = 8 + 6 + 5 + 2;
		}
		else {
			CopyMemory(responseBuffer, "Shutdown initiated.", 19);
			response.StatusCode = 200;
			response.pReason = "OK";
			response.ReasonLength = 2;
		}
		chunk.FromMemory.BufferLength = (ULONG)strlen(responseBuffer);
		result = HttpSendHttpResponse(hReqQueue, pRequest->RequestId, 0, &response, NULL, NULL, NULL, 0, NULL, NULL);
		if (result != NO_ERROR)
			ShowError(TEXT("HttpSendHttpResponse failed"));
	}
	return NO_ERROR;
}
#pragma warning(pop) 


DWORD EnablePrivileges()
{
	HANDLE hToken = NULL;
	LUID luid;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return SvcReportEvent(TEXT("OpenProcessToken"));
	}

	CONST TCHAR* privileges[2] = { SE_SHUTDOWN_NAME, SE_REMOTE_SHUTDOWN_NAME };
	for (int i = 0; i < 2; i++) {
		if (!LookupPrivilegeValue(L"", privileges[i], &luid))
			return SvcReportEvent(TEXT("LookupPrivilegeValue"));
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, 0)) {
			return SvcReportEvent(TEXT("AdjustTokenPrivileges"));
		}
	}
	return NO_ERROR;
}

DWORD RegisterService()
{
	SC_HANDLE scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!scManager) {
		DWORD err = GetLastError();
		ShowWindowsError(TEXT("OpenSCManagerA failed"), err);
		return err;
	}
	PWSTR pathBase = NULL;
	SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, NULL, &pathBase);
	TCHAR buff[MAX_PATH];

	CONST TCHAR* walk = pathBase;
	DWORD len = 0;
	while (*walk)
		buff[len++] = *walk++;
	walk = TEXT("\\Remote Shutdown\\rshutdown.exe");
	while (*walk)
		buff[len++] = *walk++;
	buff[len] = 0;


	CoTaskMemFree(pathBase);
	SC_HANDLE oldService = OpenService(scManager, ServiceName, SERVICE_ALL_ACCESS);
	if (!oldService) {
		DWORD err = GetLastError();
		if (err != ERROR_SERVICE_DOES_NOT_EXIST) {
			ShowWindowsError(TEXT("Failed to open the old service"), err);
			CloseServiceHandle(scManager);
			return err;
		}
	}
	else {
		if (!DeleteService(oldService)) {
			DWORD err = GetLastError();
			ShowWindowsError(TEXT("Failed to delete old service"), err);
			CloseServiceHandle(scManager);
			return err;
		}
		// TODO remove workaround
		Sleep(3000);
	}
	SC_HANDLE service = CreateService(
		scManager,
		ServiceName,
		TEXT("Remote Shutdown Service"),
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL,
		buff,
		NULL, NULL, NULL, NULL, NULL);
	if (!service) {
		DWORD err = GetLastError();
		ShowWindowsError(TEXT("CreateService failed"), err);
		return err;
	}
	MessageBox(NULL, TEXT("Installed service"), TEXT("Service was installed successfully"), MB_OK | MB_ICONINFORMATION);
	CloseServiceHandle(service);
	CloseServiceHandle(scManager);
	return NO_ERROR;
}

SERVICE_STATUS          gSvcStatus;
SERVICE_STATUS_HANDLE   gSvcStatusHandle;

HANDLE   hReqQueue = NULL;

VOID WINAPI Handler(DWORD dwCtrl)
{
	if (dwCtrl != SERVICE_CONTROL_STOP && dwCtrl != SERVICE_CONTROL_INTERROGATE)
		return;
	switch (gSvcStatus.dwCurrentState) {
	case SERVICE_START_PENDING:
	case SERVICE_STOP_PENDING:
		gSvcStatus.dwCheckPoint++;
		break;
	case SERVICE_RUNNING:
		if (dwCtrl == SERVICE_CONTROL_STOP) {
			HttpShutdownRequestQueue(hReqQueue);
			gSvcStatus.dwCurrentState = SERVICE_STOP_PENDING;
		}
		break;
	}
	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}


VOID WINAPI ServiceMain(DWORD dwNumServicesArgs, LPTSTR* lpServiceArgVectors)
{
	ULONG           retCode = 0;
	int             UrlAdded = 0;
	HTTPAPI_VERSION HttpApiVersion = HTTPAPI_VERSION_2;
	LPCTSTR URL = TEXT("http://localhost:3000/shutdown");


	hReqQueue = NULL;
	ZeroMemory(&gSvcStatus, sizeof gSvcStatus);
	gSvcStatusHandle = RegisterServiceCtrlHandler(ServiceName, Handler);
	if (!gSvcStatusHandle) {
		SvcReportEvent(TEXT("RegisterServiceCtrlHandlerEx"));
		return;
	}
	gSvcStatus.dwCurrentState = SERVICE_START_PENDING;
	gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	gSvcStatus.dwWaitHint = 1000; // Any X_PENDING state should not last longer than a second.

	if (!SetServiceStatus(gSvcStatusHandle, &gSvcStatus)) {
		SvcReportEvent(TEXT("SetServiceStatus"));
		goto Quit;
	}

	retCode = EnablePrivileges();
	if (retCode != NO_ERROR) {
		goto Quit;
	}

	retCode = HttpInitialize(HttpApiVersion, HTTP_INITIALIZE_SERVER, NULL);
	if (retCode != NO_ERROR) {
		goto Quit;
	}

	retCode = HttpCreateHttpHandle(&hReqQueue, 0);
	if (retCode != NO_ERROR) {
		goto Quit;
	}

	retCode = HttpAddUrl(hReqQueue, URL, NULL);
	if (retCode != NO_ERROR) {
		goto CleanUp;
	}
	gSvcStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
	retCode = DoReceiveRequests(hReqQueue);
	if (retCode != NO_ERROR) {
			SvcReportEvent(TEXT("DoReceiveRequests"));
	}

CleanUp:
	HttpRemoveUrl(hReqQueue, URL);
	if (hReqQueue) {
		CloseHandle(hReqQueue);
	}

	HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
Quit:
	gSvcStatus.dwCurrentState = SERVICE_STOPPED;
	gSvcStatus.dwWin32ExitCode = retCode;
	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
	ExitProcess(retCode);
}


void main()
{
	SERVICE_TABLE_ENTRY serviceStartTable[2] = { 0 };
	serviceStartTable[0].lpServiceName = ServiceName;
	serviceStartTable[0].lpServiceProc = ServiceMain;
	if (!StartServiceCtrlDispatcher(serviceStartTable)) {
		// If we are not running as a service, register ourselves as one.
		ULONG retCode = RegisterService();
		if (retCode != NO_ERROR) {
			ExitProcess(retCode);
		}
	}
}

