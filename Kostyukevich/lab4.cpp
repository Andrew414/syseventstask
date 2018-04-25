#include "windows.h"
#include "TlHelp32.h"
#include <fstream>
#include <iostream>
#include <string>
using namespace std;

int main() {


	ifstream deadListFile("deadList.txt");
	ofstream logFile("log.txt");

	TCHAR processName[200][MAX_PATH];
	string processNameStr[200];
	TCHAR buff[MAX_PATH];

	char charProcessName[MAX_PATH];
	int size = 0;
	
	while (deadListFile.getline(charProcessName, MAX_PATH)) {
		processNameStr[size] = charProcessName;
		mbstowcs(processName[size], charProcessName, strlen(charProcessName) + 1);
		size++;
	}
	
	HANDLE hSnapshot;
	PROCESSENTRY32 processEntry;
	BOOL result;

	cout << "tracing..." << endl << "for finish program press ctrl + c" << endl;
	
	while (true) {



		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (hSnapshot == INVALID_HANDLE_VALUE) {
			logFile << "Can't create snapshot of existing processes" << endl;
			break;
		}
		
	

		processEntry.dwSize = sizeof processEntry;
		result = Process32First(hSnapshot, &processEntry);
		
			while (result)
			{
				for (int i = 0; i < size; i++) {
					BOOL cmp = lstrcmpi(processEntry.szExeFile, processName[i]);
					if (cmp)
					{
						GetFileTitle(processEntry.szExeFile, buff, MAX_PATH);
						cmp = lstrcmpi(buff, processName[i]);
					}
					if (cmp)
					{
						GetShortPathName(processEntry.szExeFile, buff, MAX_PATH);
						cmp = lstrcmpi(buff, processName[i]);
					}
					if (!cmp)
					{

						logFile << processNameStr[i] << "  -  Find forbidden process" << endl;

						CloseHandle(hSnapshot);
						HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processEntry.th32ProcessID);
						if (hProcess == NULL) logFile << processNameStr[i] << "  -  Can't open process for termination" << endl;
				
			
						if (TerminateProcess(hProcess, 0))
						{
							WaitForSingleObject(hProcess, INFINITE);
							CloseHandle(hProcess);
							logFile << processNameStr[i] << "  -  process succesfully terminated" << endl;
							Sleep(50);
						}
			
					}
				}
				result = Process32Next(hSnapshot, &processEntry);
			}
	}


	deadListFile.close();
	logFile.close();
	CloseHandle(hSnapshot);

	return 0;
}