#include "MainForm.h"

using namespace SotInjector;
using namespace System;
using namespace System::Windows::Forms;

#pragma region Entry Point

int Main()
{
	Application::EnableVisualStyles();
	Application::SetCompatibleTextRenderingDefault(false);
	SotInjector::MainForm form;
	Application::Run(% form);

	form.Init(); // SotInjector Init
	return 0;;
}

[STAThread] // Fix OFD
int CALLBACK WinMain(

	__in  HINSTANCE hInstance,

	__in  HINSTANCE hPrevInstance,

	__in  LPSTR lpCmdLine,

	__in  int nCmdShow

)

{
	return Main();

}

#pragma endregion

namespace SotInjector {
	using namespace System;
	using namespace System::Windows::Forms;

	void MainForm::Init()
	{
		void* ProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 ProcessEntry;
		ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(ProcessSnapshot, &ProcessEntry))
		{
			while (Process32Next(ProcessSnapshot, &ProcessEntry))
			{
				void* ProcessHandle = OpenProcess(
					PROCESS_QUERY_LIMITED_INFORMATION,
					false,
					ProcessEntry.th32ProcessID
				);
				if (ProcessHandle)
				{
					std::uint32_t NameLength = 0;
					std::int32_t ProcessCode = GetPackageFamilyName(
						ProcessHandle, &NameLength, nullptr
					);
					if (ProcessCode && NameLength)
					{
						String^ pname = msclr::interop::marshal_as<System::String^>(ProcessEntry.szExeFile);
						if (pname == "SoTGame.exe")
						{
							ProcID = ProcessEntry.th32ProcessID;
						}
					}
				}
				CloseHandle(ProcessHandle);
			}
		}
		else
		{

		}

		if (ProcID == 0)
		{
			MessageBox::Show("You must run an UWP version of Sea Of Thieves first !", nullptr,MessageBoxButtons::OK, MessageBoxIcon::Error);
			Environment::Exit(0);
		}
	}

#pragma region Injection

	bool DLLInjectRemote(uint32_t ProcessID, const std::wstring& DLLpath)
	{
		const std::size_t DLLPathSize = ((DLLpath.size() + 1) * sizeof(wchar_t));
		std::uint32_t Result;
		if (!ProcessID)
		{
			MessageBox::Show("Invalid Process ID: " + ProcessID, nullptr, MessageBoxButtons::OK, MessageBoxIcon::Error);
			return false;
		}

		if (GetFileAttributesW(DLLpath.c_str()) == INVALID_FILE_ATTRIBUTES)
		{
			auto pathstring = msclr::interop::marshal_as<String^>(DLLpath);
			MessageBox::Show("DLL file: " + pathstring + " does not exists", nullptr, MessageBoxButtons::OK, MessageBoxIcon::Error);
			return false;
		}

		SetAccessControl(DLLpath, L"S-1-15-2-1");

		void* ProcLoadLibrary = reinterpret_cast<void*>(
			GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW")
			);

		if (!ProcLoadLibrary)
		{
			MessageBox::Show("Unable to find LoadLibraryW procedure", nullptr, MessageBoxButtons::OK, MessageBoxIcon::Error);
			return false;
		}

		auto Process = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessID);
		if (Process == nullptr)
		{
			MessageBox::Show("Unable to open process ID " + ProcessID + " for writing", nullptr, MessageBoxButtons::OK, MessageBoxIcon::Error);
			return false;
		}
		void* VirtualAlloc = reinterpret_cast<void*>(
			VirtualAllocEx(
				Process,
				nullptr,
				DLLPathSize,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_READWRITE
			)
			);

		if (VirtualAlloc == nullptr)
		{
			MessageBox::Show("Unable to remotely allocate memory");
			CloseHandle(Process);
			return false;
		}

		SIZE_T BytesWritten = 0;
		Result = WriteProcessMemory(
			Process,
			VirtualAlloc,
			DLLpath.data(),
			DLLPathSize,
			&BytesWritten
		);

		if (Result == 0)
		{
			MessageBox::Show("Unable to write process memory");
			CloseHandle(Process);
			return false;
		}

		if (BytesWritten != DLLPathSize)
		{
			MessageBox::Show("Failed to write remote DLL path name");
			CloseHandle(Process);
			return false;
		}

		void* RemoteThread =
			CreateRemoteThread(
				Process,
				nullptr,
				0,
				reinterpret_cast<LPTHREAD_START_ROUTINE>(ProcLoadLibrary),
				VirtualAlloc,
				0,
				nullptr
			);

		// Wait for remote thread to finish
		if (RemoteThread)
		{
			// Explicitly wait for LoadLibraryW to complete before releasing memory
			// avoids causing a remote memory leak
			WaitForSingleObject(RemoteThread, INFINITE);
			CloseHandle(RemoteThread);
		}
		else
		{
			// Failed to create thread
			MessageBox::Show("Unable to create remote thread", nullptr, MessageBoxButtons::OK, MessageBoxIcon::Error);
		}

		VirtualFreeEx(Process, VirtualAlloc, 0, MEM_RELEASE);
		CloseHandle(Process);
		return true;
	}

	void SetAccessControl(const std::wstring& ExecutableName, const wchar_t* AccessString)
	{
		PSECURITY_DESCRIPTOR SecurityDescriptor = nullptr;
		EXPLICIT_ACCESSW ExplicitAccess = { 0 };

		ACL* AccessControlCurrent = nullptr;
		ACL* AccessControlNew = nullptr;

		SECURITY_INFORMATION SecurityInfo = DACL_SECURITY_INFORMATION;
		PSID SecurityIdentifier = nullptr;

		if (
			GetNamedSecurityInfoW(
				ExecutableName.c_str(),
				SE_FILE_OBJECT,
				DACL_SECURITY_INFORMATION,
				nullptr,
				nullptr,
				&AccessControlCurrent,
				nullptr,
				&SecurityDescriptor
			) == ERROR_SUCCESS
			)
		{
			ConvertStringSidToSidW(AccessString, &SecurityIdentifier);
			if (SecurityIdentifier != nullptr)
			{
				ExplicitAccess.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE | GENERIC_WRITE;
				ExplicitAccess.grfAccessMode = SET_ACCESS;
				ExplicitAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
				ExplicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
				ExplicitAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
				ExplicitAccess.Trustee.ptstrName = reinterpret_cast<wchar_t*>(SecurityIdentifier);

				if (
					SetEntriesInAclW(
						1,
						&ExplicitAccess,
						AccessControlCurrent,
						&AccessControlNew
					) == ERROR_SUCCESS
					)
				{
					SetNamedSecurityInfoW(
						const_cast<wchar_t*>(ExecutableName.c_str()),
						SE_FILE_OBJECT,
						SecurityInfo,
						nullptr,
						nullptr,
						AccessControlNew,
						nullptr
					);
				}
			}
		}
		if (SecurityDescriptor)
		{
			LocalFree(reinterpret_cast<HLOCAL>(SecurityDescriptor));
		}
		if (AccessControlNew)
		{
			LocalFree(reinterpret_cast<HLOCAL>(AccessControlNew));
		}
	}

#pragma endregion
}