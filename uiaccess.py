# coding = 'utf-8'

'''
获取 UI Access

原理：

uiaccess

https://github.com/killtimer0/uiaccess

【揭秘窗口置顶中的『等级制度』！窗口Z序和UIAccess又是什么?】 

https://www.bilibili.com/video/BV1HCwwegEVp/?share_source=copy_web&vd_source=d9b0a480a8ddccc1515316b991134fda

'''

# method: https://github.com/QwQr-dev/method

from method.core.windows import *

if WIN32_WINNT < WIN32_WINNT_WIN8:
    raise OSError('Do not supported system.')


def DuplicateWinloginToken(dwSessionId, dwDesiredAccess):
    ps = PRIVILEGE_SET()
    ps.PrivilegeCount = 1
    ps.Control =  PRIVILEGE_SET_ALL_NECESSARY

    LookupPrivilegeValue(NULL, SE_TCB_NAME, byref(ps.Privilege[0].Luid))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    pe = PROCESSENTRY32W()
    pe.dwSize = sizeof(pe)

    Process32First(hSnapshot, byref(pe))

    while True:
        if pe.szExeFile.lower() != 'winlogon.exe':
            Process32Next(hSnapshot, byref(pe))
            continue

        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pe.th32ProcessID)

        hToken = HANDLE()
        OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, byref(hToken))

        fTcb = BOOL()
        PrivilegeCheck(hToken, byref(ps), byref(fTcb))

        sid = DWORD()
        dwRetLen = DWORD()

        GetTokenInformation(hToken, TokenSessionId, byref(sid), sizeof(sid), byref(dwRetLen))
        if sid.value == dwSessionId.value:
            hTokenDup = HANDLE()
            DuplicateTokenEx(hToken, dwDesiredAccess, NULL, SecurityImpersonation, TokenImpersonation, byref(hTokenDup))
            hTokenResult = hTokenDup

        CloseHandle(hToken)
        CloseHandle(hProcess)

        if hTokenResult:
            break

    CloseHandle(hSnapshot)
    return hTokenResult


def CreateUIAccessToken():
    hTokenSelf = HANDLE()
    OpenProcessToken(GetCurrentProcess(), 
                     TOKEN_QUERY | TOKEN_DUPLICATE, 
                     byref(hTokenSelf)
    )

    dwSessionId = DWORD()
    dwRetLen = DWORD()

    GetTokenInformation(hTokenSelf, 
                        TokenSessionId, 
                        byref(dwSessionId), 
                        sizeof(dwSessionId), 
                        byref(dwRetLen))
        
    hTokenSystem = DuplicateWinloginToken(dwSessionId, TOKEN_IMPERSONATE)

    SetThreadToken(NULL, hTokenSystem)
    hTokenUIAccess = HANDLE()

    DuplicateTokenEx(hTokenSelf, 
                     TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, 
                     NULL, 
                     SecurityAnonymous, 
                     TokenPrimary, 
                     byref(hTokenUIAccess)
    )

    bUIAccess = BOOL(True)

    SetTokenInformation(hTokenUIAccess, 
                        TokenUIAccess, 
                        byref(bUIAccess), 
                        sizeof(bUIAccess)
    )

    RevertToSelf()

    CloseHandle(hTokenSystem)
    CloseHandle(hTokenSelf)
    return hTokenUIAccess


def PrepareForUIAccess():
    hToken = HANDLE()
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, byref(hToken))

    dwUIAccess = BOOL()
    dwRetLen = DWORD()

    GetTokenInformation(hToken, TokenUIAccess, byref(dwUIAccess), sizeof(dwUIAccess), byref(dwRetLen))
    if dwUIAccess.value:
        CloseHandle(hToken)
        return
        
    CloseHandle(hToken)

    hTokenUIAccess = CreateUIAccessToken()
    si = STARTUPINFOW()
    pi = PROCESS_INFORMATION()
    si.cb = sizeof(STARTUPINFOW)

    CreateProcessAsUser(hTokenUIAccess, 
                        NULL, 
                        GetCommandLine(), 
                        NULL, 
                        NULL, 
                        False, 
                        NULL, 
                        NULL, 
                        NULL,   
                        byref(si), 
                        byref(pi)
    )

    CloseHandle(pi.hProcess)
    CloseHandle(pi.hThread)
    CloseHandle(hTokenUIAccess)
    sys.exit(0)


UIAccess = PrepareForUIAccess


if __name__ == '__main__':
    # test
    # 提示：使用 Process Explorer 并在 “ 视图（View） -> 选择显示的项目（Select Columns）-> Process Image ” 勾选 “ 用户界面访问（UI Access）” 即可查看

    from method import RunAsAdmin

    RunAsAdmin()
    UIAccess()
    si = STARTUPINFOW()
    si.cb = sizeof(si)
    si.dwFlags = DEBUG_PROCESS
    si.wShowWindow = DEBUG_PROCESS

    CreateProcess(NULL, 
                  f'c:\\windows\\system32\\cmd.exe', 
                  NULL, 
                  NULL, 
                  FALSE, 
                  CREATE_NEW_CONSOLE, 
                  NULL, 
                  NULL, 
                  byref(si),
                  byref(VOID())
    )

