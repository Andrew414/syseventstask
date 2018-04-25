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
	PROCESSENTRY32 pe;
	BOOL result;

	cout << "tracing..." << endl << "for finish program press ctrl + c" << endl;
	
	while (true) {



		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (hSnapshot == INVALID_HANDLE_VALUE) {
			logFile << "Can't create snapshot of existing processes" << endl;
			break;
		}
		
	

		pe.dwSize = sizeof pe;
		result = Process32First(hSnapshot, &pe);
		
			while (result)
			{
				for (int i = 0; i < size; i++) {
					BOOL eq = lstrcmpi(pe.szExeFile, processName[i]);
					if (eq)
					{
						GetFileTitle(pe.szExeFile, buff, MAX_PATH);
						eq = lstrcmpi(buff, processName[i]);
					}
					if (eq)
					{
						GetShortPathName(pe.szExeFile, buff, MAX_PATH);
						eq = lstrcmpi(buff, processName[i]);
					}
					if (!eq)
					{

						logFile << processNameStr[i] << "  -  Find forbidden process" << endl;

						CloseHandle(hSnapshot);
						HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
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
				result = Process32Next(hSnapshot, &pe);
			}
	}


	deadListFile.close();
	logFile.close();
	CloseHandle(hSnapshot);

	return 0;
}