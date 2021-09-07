#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <Shlobj.h>
#include <http.h>
#include <stdio.h>

void showError(LPCTSTR error) {
	MessageBox(NULL, error, TEXT("Error"), MB_OK | MB_ICONERROR);
}
void ShowError(LPCTSTR title, const DWORD err) {
	CHAR buff[1024];
	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), buff, sizeof buff / sizeof(TCHAR), NULL);
	MessageBoxA(NULL, buff, "title", MB_OK | MB_ICONERROR);
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
#endif

#pragma warning(push)
#pragma warning(disable:28159)
DWORD DoReceiveRequests(HANDLE hReqQueue) {
	for (;;) {
		char RequestBuffer[sizeof(HTTP_REQUEST) + 2048] = { 0 };
		PHTTP_REQUEST_V1 pRequest = (PHTTP_REQUEST_V1)RequestBuffer;
		ULONG result = HttpReceiveHttpRequest(hReqQueue, 0, 0, (PHTTP_REQUEST)pRequest, sizeof RequestBuffer, NULL, NULL);
		if (result != NO_ERROR)
			return result;

		if (pRequest->Verb != HttpVerbPOST) {
			HTTP_RESPONSE response = { 0 };
			LPCSTR reason = "Not implemented";
			response.StatusCode = 503;
			response.pReason = reason;
			response.ReasonLength = (USHORT)strlen(reason);
			result = HttpSendHttpResponse(hReqQueue, pRequest->RequestId, HTTP_SEND_RESPONSE_FLAG_DISCONNECT, &response, NULL, NULL, NULL, 0UL, NULL, NULL);
			if (result != NO_ERROR)
				showError(TEXT("Error sending HTTP response"));
			continue;
		}

		CHAR message[] = "Remote shutdown triggered";
		CHAR responseBuffer[255] = { 0 };
		BOOL ok = InitiateSystemShutdownExA(NULL, message, 100, TRUE, FALSE, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER);
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
		chunk.FromMemory.BufferLength = (ULONG) strlen(responseBuffer);
		result = HttpSendHttpResponse(hReqQueue, pRequest->RequestId, 0, &response, NULL, NULL, NULL, 0, NULL, NULL);
		if (result != NO_ERROR)
			showError(TEXT("HttpSendHttpResponse failed"));
	}
	return NO_ERROR;
}
#pragma warning(pop) 

void enableShutdownPrivilege()
{
	HANDLE hToken = NULL;
	LUID luid;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);

	CONST TCHAR *privileges[2] = { SE_SHUTDOWN_NAME, SE_REMOTE_SHUTDOWN_NAME };
	for (int i = 0; i < 2; i++) {
		LookupPrivilegeValue(L"", privileges[i], &luid);
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, 0))
			showError(TEXT("AdjustTokenPrivileges failed"));
	}
}

void createService()
{
	SC_HANDLE scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!scManager) {
		ShowError(TEXT("OpenSCManagerA failed"), GetLastError());
		return;
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


	ShowError(TEXT("Permission denied test"), 0x5);
	CoTaskMemFree(pathBase);
	showError(buff);
	SC_HANDLE service = CreateService(scManager, TEXT("Remote Shutdown Server"), TEXT("RemoteShutdownService"), SC_MANAGER_ALL_ACCESS, 0, 0, 0, buff, NULL, NULL, NULL, NULL, NULL);
	if (!service)
		ShowError(TEXT("CreateService failed"), GetLastError());
}

void main() {
	ULONG           retCode;
	HANDLE          hReqQueue = NULL;
	int             UrlAdded = 0;
	HTTPAPI_VERSION HttpApiVersion = HTTPAPI_VERSION_2;
	LPCTSTR URL = TEXT("http://localhost:3000/shutdown");


	createService();

	enableShutdownPrivilege();

	retCode = HttpInitialize(HttpApiVersion, HTTP_INITIALIZE_SERVER, NULL);
	if (retCode != NO_ERROR) {
		ExitProcess(retCode);
	}

	retCode = HttpCreateHttpHandle(&hReqQueue, 0);
	if (retCode != NO_ERROR) {
		goto CleanUp;
	}

	retCode = HttpAddUrl(hReqQueue, URL, NULL);
	if (retCode != NO_ERROR) {
		goto CleanUp;
	}
	DoReceiveRequests(hReqQueue);

CleanUp:
	HttpRemoveUrl(hReqQueue, URL);
	if (hReqQueue) {
		CloseHandle(hReqQueue);
	}

	HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
	ExitProcess(retCode);
}

