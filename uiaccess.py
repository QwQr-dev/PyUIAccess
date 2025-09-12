# coding = 'utf-8'

import tkinter as tk
from method import *
from method.core.windows import *

# 原理：https://github.com/killtimer0/uiaccess


def AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength):
    AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
    res = AdjustTokenPrivileges(TokenHandle, 
                                DisableAllPrivileges, 
                                NewState, 
                                BufferLength, 
                                PreviousState, 
                                ReturnLength
    )

    if not res:
        raise WinError(GetLastError())


def DefWindowProc(hwnd, message, wParam, lParam, unicode: bool = True) -> int:
    DefWindowProc = (User32.DefWindowProcW 
                     if unicode else User32.DefWindowProcA
    )

    DefWindowProc.argtypes = [HWND, UINT, WPARAM, LPARAM]
    DefWindowProc.restype = LRESULT
    res = DefWindowProc(hwnd, message, wParam, lParam)
    return res


def DuplicateWinloginToken(dwSessionId, dwDesiredAccess):
    ps = PRIVILEGE_SET()
    ps.PrivilegeCount = 1
    ps.Control = PRIVILEGE_SET_ALL_NECESSARY

    # hToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
    
    luid = LookupPrivilegeValue(NULL, SE_TCB_NAME)

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PROCESSENTRY32W()
    pe.dwSize = sizeof(pe)
    Process32First(hSnapshot, byref(pe))

    while True:
        if pe.szExeFile.lower() != "winlogon.exe":
            Process32Next(hSnapshot, byref(pe))
            continue
        
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID)
        sid = DWORD()

        hToken = OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE)

        AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(tp), NULL, NULL)

        RequiredPrivileges, pfResult = PrivilegeCheck(hToken, byref(ps))

        if pfResult:    # error 
            sid = GetTokenInformation(hToken, TokenSessionId, sizeof(sid)) 
            if sid == dwSessionId:
                DuplicateTokenEx(hToken, dwDesiredAccess, NULL, SecurityImpersonation, TokenImpersonation)

        CloseHandle(hToken)
        CloseHandle(hProcess)
        break
    CloseHandle(hSnapshot)


def CreateUIAccessToken():
    hTokenSelf = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE)
    dwSessionId = DWORD()

    dwSessionId = GetTokenInformation(hTokenSelf, TokenSessionId, sizeof(dwSessionId))

    hTokenSystem = HANDLE()

    DuplicateWinloginToken(dwSessionId, TOKEN_IMPERSONATE)

    SetThreadToken(NULL, hTokenSystem)
    phToken = DuplicateTokenEx(hTokenSelf, 
                               TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, 
                               NULL, 
                               SecurityAnonymous, 
                               TokenPrimary
    )

    bUIAccess = BOOL(TRUE)

    SetTokenInformation(phToken, TokenUIAccess, byref(bUIAccess), sizeof(bUIAccess))

    try:
        pass
    except Exception as e:
        raise OSError(e)
    finally:
        CloseHandle(phToken)
    
    RevertToSelf()
    CloseHandle(hTokenSystem)
    CloseHandle(hTokenSelf)


def CheckForUIAccess():
    fUIAccess = BOOL()
    hToken = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY)
    GetTokenInformation(hToken, TokenUIAccess, byref(fUIAccess))
    CloseHandle(hToken)


def PrepareForUIAccess():
    # 获取19号关机特权
    # RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, byref(BOOLEAN()))
    hTokenUIAccess = HANDLE()
    
    CreateUIAccessToken()

    si = GetStartupInfo()
    pi = CreateProcessAsUser(hTokenUIAccess, 
                             LPCWSTR(), 
                             GetCommandLine(), 
                             NULL, 
                             NULL, 
                             FALSE, 
                             DWORD(), 
                             NULL,
                             NULL, 
                             byref(si)
    )

    pi = pi['lpProcessInformation']

    CloseHandle(pi.hProcess)
    CloseHandle(pi.hThread)
    # ExitProcess(0)
    # CloseHandle(hTokenUIAccess)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.mainloop()


if __name__ == '__main__':
    # Temp failed
    PrepareForUIAccess()
    # OverlayWindow = GetForegroundWindow()
    # App()
    # SetWindowPos(NULL, HWND_TOPMOST, NULL, NULL, NULL, NULL, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    # ShowWindow(OverlayWindow, SW_NORMAL)
    # UpdateWindow(OverlayWindow)