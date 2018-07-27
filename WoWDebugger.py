from time import sleep
from ctypes import *
from ctypes.wintypes import *
import win32con
import psutil
import win32security
import win32process
import struct

Psapi = WinDLL('Psapi.dll')
ntdll = WinDLL('ntdll')

DWORD64 = c_ulonglong
DWORD = c_ulong
WORD = c_ushort

CONTEXT_AMD64 = 0x100000
CONTEXT_CONTROL = (CONTEXT_AMD64 | 0x1L)
CONTEXT_INTEGER = (CONTEXT_AMD64 | 0x2L)
CONTEXT_SEGMENTS = (CONTEXT_AMD64 | 0x4L)
CONTEXT_FLOATING_POINT = (CONTEXT_AMD64 | 0x8L)
CONTEXT_DEBUG_REGISTERS = (CONTEXT_AMD64 | 0x10L)

CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)

CONTEXT_ALL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)

CONTEXT_XSTATE = (CONTEXT_AMD64 | 0x20L)

class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize",             DWORD),
        ("cntUsage",           DWORD),
        ("th32ThreadID",       DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri",          DWORD),
        ("tpDeltaPri",         DWORD),
        ("dwFlags",            DWORD),
    ]

class PLARGE_INTEGER(Structure):
    _fields_ = [
            ("HighPart", c_ulong),
            ("LowPart", c_ulong)
            ]

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", LPVOID),
        ("AllocationBase", LPVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", c_size_t),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]

class SECTION_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", LPVOID),
        ("AllocationAttributes", ULONG),
        ("MaximumSize", PLARGE_INTEGER),
    ]

class LPFILETIME(Structure):
    _fields_ = [
        ("dwLowDateTime", DWORD),
        ("dwHighDateTime", DWORD),
    ]

class M128A(Structure):
    _fields_ = [
            ("Low", c_ulonglong),
            ("High", c_ulonglong)
            ]

class XMM_SAVE_AREA32(Structure):
    _pack_ = 1
    _fields_ = [
                ('ControlWord', WORD),
                ('StatusWord', c_ushort ),
                ('TagWord', c_byte),
                ('Reserved1', c_byte),
                ('ErrorOpcode', c_ushort ),
                ('ErrorOffset', c_ulong),
                ('ErrorSelector', c_ushort ),
                ('Reserved2', c_ushort ),
                ('DataOffset', c_ulong),
                ('DataSelector', c_ushort ),
                ('Reserved3', c_ushort ),
                ('MxCsr', c_ulong),
                ('MxCsr_Mask', c_ulong),
                ('FloatRegisters', M128A * 8),
                ('XmmRegisters', M128A * 16),
                ('Reserved4', c_byte * 96)
                ]

class DUMMYSTRUCTNAME(Structure):
    _fields_=[
              ("Header", M128A * 2),
              ("Legacy", M128A * 8),
              ("Xmm0", M128A),
              ("Xmm1", M128A),
              ("Xmm2", M128A),
              ("Xmm3", M128A),
              ("Xmm4", M128A),
              ("Xmm5", M128A),
              ("Xmm6", M128A),
              ("Xmm7", M128A),
              ("Xmm8", M128A),
              ("Xmm9", M128A),
              ("Xmm10", M128A),
              ("Xmm11", M128A),
              ("Xmm12", M128A),
              ("Xmm13", M128A),
              ("Xmm14", M128A),
              ("Xmm15", M128A)
              ]


class DUMMYUNIONNAME(Union):
    _fields_=[
              ("FltSave", XMM_SAVE_AREA32),
              ("DummyStruct", DUMMYSTRUCTNAME)
              ]

class CONTEXT64(Structure):
    _pack_ = 16
    _fields_ = [
                ("P1Home", DWORD64),
                ("P2Home", DWORD64),
                ("P3Home", DWORD64),
                ("P4Home", DWORD64),
                ("P5Home", DWORD64),
                ("P6Home", DWORD64),
                ("ContextFlags", DWORD),
                ("MxCsr", DWORD),
                ("SegCs", WORD),
                ("SegDs", WORD),
                ("SegEs", WORD),
                ("SegFs", WORD),
                ("SegGs", WORD),
                ("SegSs", WORD),
                ("EFlags", DWORD),
                ("Dr0", DWORD64),
                ("Dr1", DWORD64),
                ("Dr2", DWORD64),
                ("Dr3", DWORD64),
                ("Dr6", DWORD64),
                ("Dr7", DWORD64),
                ("Rax", DWORD64),
                ("Rcx", DWORD64),
                ("Rdx", DWORD64),
                ("Rbx", DWORD64),
                ("Rsp", DWORD64),
                ("Rbp", DWORD64),
                ("Rsi", DWORD64),
                ("Rdi", DWORD64),
                ("R8", DWORD64),
                ("R9", DWORD64),
                ("R10", DWORD64),
                ("R11", DWORD64),
                ("R12", DWORD64),
                ("R13", DWORD64),
                ("R14", DWORD64),
                ("R15", DWORD64),
                ("Rip", DWORD64),
                ("DUMMYUNIONNAME", DUMMYUNIONNAME),
                ("DebugControl", DWORD64),
                ("LastBranchToRip", DWORD64),
                ("LastBranchFromRip", DWORD64),
                ("LastExceptionToRip", DWORD64),
                ("LastExceptionFromRip", DWORD64),
                ("VectorRegister", M128A * 26),
                ("VectorControl", DWORD64)
]


class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize",             DWORD),
        ("cntUsage",           DWORD),
        ("th32ThreadID",       DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri",          DWORD),
        ("tpDeltaPri",         DWORD),
        ("dwFlags",            DWORD),
    ]

TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
THREAD_ALL_ACCESS   = 0x001F03FF
FILE_MAP_ALL_ACCESS = 0xF001F

THREAD_ACCESS_RIGHTS = (0x0008 | 0x0002 | 0x0010 | win32con.THREAD_QUERY_INFORMATION)

PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_EXECUTE_READWRITE = 0x00000040
PAGE_READ_EXECUTE = 0x20
VIRTUAL_MEM = ( 0x1000 | 0x2000 )

OpenThread = windll.kernel32.OpenThread
GetThreadContext = windll.kernel32.GetThreadContext
ResumeThread = windll.kernel32.ResumeThread
SetThreadContext = windll.kernel32.SetThreadContext
Wow64SuspendThread = windll.kernel32.Wow64SuspendThread
SuspendThread = windll.kernel32.SuspendThread
Wow64GetThreadContext = windll.kernel32.Wow64GetThreadContext
CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
Thread32First = windll.kernel32.Thread32First
Thread32Next = windll.kernel32.Thread32Next
OpenProcess = windll.kernel32.OpenProcess
ReadProcessMemory = windll.kernel32.ReadProcessMemory
WriteProcessMemory = windll.kernel32.WriteProcessMemory
CloseHandle = windll.kernel32.CloseHandle
NtCreateSection = ntdll.NtCreateSection
NtMapViewOfSection = ntdll.NtMapViewOfSection
NtUnmapViewOfSection = ntdll.NtUnmapViewOfSection
NtQuerySection = ntdll.NtQuerySection
EnumProcessModulesEx = Psapi.EnumProcessModulesEx
VirtualQueryEx = windll.kernel32.VirtualQueryEx
OpenFileMappingW = windll.kernel32.OpenFileMappingW
GetThreadTimes = windll.kernel32.GetThreadTimes
VirtualAllocEx = windll.kernel32.VirtualAllocEx

VirtualQueryEx.argtypes = [HANDLE, LPCVOID, POINTER(MEMORY_BASIC_INFORMATION), c_size_t]
VirtualQueryEx.restype = ULONG

OpenThread.argtypes = [DWORD, BOOL, DWORD]
OpenThread.restype = HANDLE

Wow64SuspendThread.argtypes = [HANDLE]
Wow64SuspendThread.restype = DWORD

ResumeThread.argtypes = [HANDLE]
ResumeThread.restype = DWORD

GetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT64)]
GetThreadContext.restype = INT

Thread32First.argtypes = [HANDLE, POINTER(THREADENTRY32)]
Thread32First.restype = BOOL

Thread32Next.argtypes = [HANDLE, POINTER(THREADENTRY32)]
Thread32Next.restype = BOOL

ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, c_size_t, POINTER(c_size_t)]
ReadProcessMemory.restype = BOOL

WriteProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, c_size_t, POINTER(c_size_t)]
WriteProcessMemory.restype = BOOL

NtCreateSection.argtypes = [POINTER(HANDLE), ULONG, LPCVOID, LPCVOID, ULONG, ULONG, HANDLE]
NtCreateSection.restype = HANDLE

NtMapViewOfSection.argtypes = [HANDLE, HANDLE, LPVOID, LPVOID, c_size_t, PLARGE_INTEGER, POINTER(c_size_t), DWORD, ULONG, ULONG]
NtMapViewOfSection.restype = BOOL

NtUnmapViewOfSection.argtypes = [HANDLE, LPCVOID]
NtUnmapViewOfSection.restype = BOOL

NtQuerySection.argtypes = [HANDLE, POINTER(SECTION_BASIC_INFORMATION), POINTER(LPVOID), ULONG, POINTER(ULONG)]
NtQuerySection.restype = BOOL

EnumProcessModulesEx.restype = c_bool
EnumProcessModulesEx.argtypes = [c_void_p, POINTER(c_void_p), c_ulong, POINTER(c_ulong), c_int]

GetThreadTimes.argtypes = [HANDLE, POINTER(LPFILETIME), POINTER(LPFILETIME), POINTER(LPFILETIME), POINTER(LPFILETIME)]
GetThreadTimes.restype = BOOL

VirtualAllocEx.argtypes = [HANDLE, LPVOID, c_size_t, DWORD, DWORD]
VirtualAllocEx.restype = LPCVOID


currentProcessHandle = windll.kernel32.GetCurrentProcess()
flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
currentProcessToken = win32security.OpenProcessToken(currentProcessHandle, flags)
id1 = win32security.LookupPrivilegeValue(None, "seDebugPrivilege")
id2 = win32security.LookupPrivilegeValue(None, win32security.SE_LOCK_MEMORY_NAME)
newPrivileges = [(id1, win32security.SE_PRIVILEGE_ENABLED)]
win32security.AdjustTokenPrivileges(currentProcessToken, 0, newPrivileges)


#FUNCTIONS

def get_client_pid(process_name):
    pid = None
    wowpids = []
    for proc in psutil.process_iter():
        if proc.name() == process_name:
            pid = int(proc.pid)
            print "Found, PID = " + str(pid)
            wowpids.append(pid)
    if len(wowpids) > 1:
        print "Multiple processes found, choose one"
        while True:
            for wow in wowpids:
                print wow
                question = raw_input("Choose this process? Y/N ")
                if question == 'Y':
                    return wow
                elif question == 'N':
                    continue
                else:
                    print "Incorrect answer, try again"
                    break
    return pid


def setProcessHandle(pid):
    global processHandle
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)

def getBaseAddress():
    global baseaddress
    global sizeofmodule
    processarray = (c_void_p *2056)()
    bytesReader = c_ulong()
    enumprocess = EnumProcessModulesEx(processHandle, processarray, sizeof(processarray), byref(bytesReader), 0x02)

    for module in processarray:
        getfilename = win32process.GetModuleFileNameEx(processHandle, module)
        if "Wow.exe" in getfilename and module != None:
            baseaddress = module
            memorybasicinfo = MEMORY_BASIC_INFORMATION()
            VirtualQueryEx(processHandle, baseaddress, byref(memorybasicinfo), sizeof(memorybasicinfo))
            sizeofmodule = memorybasicinfo.RegionSize
            break

def findAllThread(pido):
    #print GetLastError()
    #print "FindAllThreads"
    threadarray = []
    thread_entry = THREADENTRY32()
    snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, pido)
    thread_entry.dwSize = sizeof(THREADENTRY32)
    success = Thread32First(snapshotHandle, byref(thread_entry))
    while success:
        if thread_entry.th32OwnerProcessID == pido:
            threadarray.append(thread_entry.th32ThreadID)
        success = Thread32Next(snapshotHandle, byref(thread_entry))
    else:
        pass
    CloseHandle(snapshotHandle)
    return threadarray

def MemoryRemap():
    print "Remapping memory"
    threadarray = findAllThread(pid)
    #print len(threadarray)
    for threadd in threadarray:
        threadHandle = OpenThread(THREAD_ACCESS_RIGHTS, False, threadd)
        Wow64SuspendThread(threadHandle)
        CloseHandle(threadHandle)
    sleep(2)
    wowimagesizetocopy = sizeofmodule
    buffer = (c_ubyte*wowimagesizetocopy)()
    bytesRead = c_ulonglong()
    SECTION_ALL_ACCESS = (win32con.SECTION_MAP_EXECUTE | win32con.SECTION_MAP_READ | win32con.SECTION_MAP_WRITE)
    largeint = PLARGE_INTEGER()
    largeint.HighPart = 0
    largeint.LowPart = 0x1
    thissection = c_void_p()
    anotherlargeint = PLARGE_INTEGER()
    anotherlargeint.HighPart = 0
    anotherlargeint.LowPart = 0
    sizee = c_size_t(wowimagesizetocopy)
    baseaddresss = c_voidp(0)
    baseadresspointer = c_voidp(baseaddress)
    NtCreateSection(byref(thissection), SECTION_ALL_ACCESS, 0, byref(largeint), win32con.PAGE_EXECUTE_READWRITE, win32con.SEC_COMMIT, 0)
    NtMapViewOfSection(thissection.value, processHandle, byref(baseaddresss), 0, 0, anotherlargeint, byref(sizee), 1, 0, win32con.PAGE_EXECUTE_READWRITE)
    if ReadProcessMemory(processHandle, baseaddress, buffer, sizeof(buffer), byref(bytesRead)):
        if WriteProcessMemory(processHandle, baseaddresss.value, buffer, sizeof(buffer), byref(bytesRead)):
            pass
        else:
            "Memory remap failed, couldnt write memory"
            return False
    else:
        "Memory remap failed, couldnt read memory"
        return False
    NtUnmapViewOfSection(processHandle, baseaddresss.value)
    NtUnmapViewOfSection(processHandle, baseaddress)
    NtMapViewOfSection(thissection.value, processHandle, byref(baseadresspointer), 0, 0, anotherlargeint, byref(sizee), 1, 0, win32con.PAGE_EXECUTE_READWRITE)
    sleep(2)
    for threadd in threadarray:
        threadHandle = OpenThread(THREAD_ACCESS_RIGHTS, False, threadd)
        ResumeThread(threadHandle)
        CloseHandle(threadHandle)
    CloseHandle(thissection)
    print "Memory remap was successful"
    return True

def MakeULONGLONG(ldw, hdw):
   result = (hdw << 32 | (ldw & 0xFFFFFFFF))
   return result

def findMainThread(pido):
    thread_entry = THREADENTRY32()
    snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, pido)
    thread_entry.dwSize = sizeof(THREADENTRY32)
    #print snapshotHandle
    #print thread_entry.dwSize
    success = Thread32First(snapshotHandle, byref(thread_entry))
    bestcreationtime = 9999999999999999999999999999
    while success:
        if thread_entry.th32OwnerProcessID == pido:
            threadHandle = OpenThread(THREAD_ACCESS_RIGHTS, False, thread_entry.th32ThreadID)
            creationTime = LPFILETIME()
            exittime = LPFILETIME()
            kerneltime = LPFILETIME()
            usertime = LPFILETIME()
            GetThreadTimes(threadHandle, byref(creationTime), byref(exittime), byref(kerneltime), byref(usertime))
            creationTime.dwLowDateTime
            creationTime.dwHighDateTime
            thiscreattiontime = MakeULONGLONG(creationTime.dwLowDateTime, creationTime.dwHighDateTime)
            if thiscreattiontime < bestcreationtime:
                bestcreationtime = thiscreattiontime
                mainthreadID = thread_entry.th32ThreadID
        success = Thread32Next(snapshotHandle, byref(thread_entry))
    CloseHandle(snapshotHandle)
    print mainthreadID
    return mainthreadID

def CheckRegisters(threadhandletocheck):
    #findgoodthread = findMainThread(pid)
    #threadHandle = OpenThread((THREAD_ACCESS_RIGHTS), False, findgoodthread)
    threadcontext = CONTEXT64()
    threadcontext.ContextFlags = (CONTEXT_ALL | CONTEXT_XSTATE)
    GetThreadContext(threadhandletocheck, threadcontext)
    #GetLastError()
    #currentRax = threadcontext.Rax
    currentRcx = threadcontext.Rcx
    currentRdx = threadcontext.Rdx
    currentRbx = threadcontext.Rbx
    currentRSP = threadcontext.Rsp
    currentRBP = threadcontext.Rbp
    currentRIP = threadcontext.Rip
    currentRdi = threadcontext.Rdi
    currentR8 = threadcontext.R8
    currentR9 = threadcontext.R9
    currentR10 = threadcontext.R10
    currentR11 = threadcontext.R11
    currentR12 = threadcontext.R12
    currentR13 = threadcontext.R13
    currentR14 = threadcontext.R14
    currentR15 = threadcontext.R15

    currentXMM0High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm0.High
    currentXMM0Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm0.Low
    currentXMM1High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm1.High
    currentXMM1Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm1.Low
    currentXMM2High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm2.High
    currentXMM2Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm2.Low
    currentXMM3High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm3.High
    currentXMM3Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm3.Low
    currentXMM4High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm4.High
    currentXMM4Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm4.Low
    currentXMM5High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm5.High
    currentXMM5Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm5.Low
    currentXMM6High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm6.High
    currentXMM6Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm6.Low
    currentXMM7High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm7.High
    currentXMM7Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm7.Low
    currentXMM8High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm8.High
    currentXMM8Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm8.Low
    currentXMM9High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm9.High
    currentXMM9Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm9.Low
    currentXMM10High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm10.High
    currentXMM10Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm10.Low
    currentXMM11High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm11.High
    currentXMM11Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm11.Low
    currentXMM12High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm12.High
    currentXMM12Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm12.Low
    currentXMM13High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm13.High
    currentXMM13Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm13.Low
    currentXMM14High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm14.High
    currentXMM14Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm14.Low
    currentXMM15High = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm15.High
    currentXMM15Low = threadcontext.DUMMYUNIONNAME.DummyStruct.Xmm15.Low

    MxCsr = threadcontext.MxCsr
    ContextFlags = threadcontext.ContextFlags
    ControlWord = threadcontext.DUMMYUNIONNAME.FltSave.ControlWord
    EFlags = threadcontext.EFlags


    dr0 = threadcontext.Dr0
    dr1 = threadcontext.Dr1
    dr2 = threadcontext.Dr2
    dr3 = threadcontext.Dr3
    dr6 = threadcontext.Dr6
    dr7 = threadcontext.Dr7

    #print currentRIP

    currentRax = c_longlong()
    bytesRead = c_ulonglong()
    ReadProcessMemory(processHandle, raxregisterstorage, byref(currentRax), 8, byref(bytesRead))


    print "Registers Values:"

    #print 'Rax: ' + hex(currentRax)
    print 'Rax: ' + hex(currentRax.value)
    print 'Rcx: ' + hex(currentRcx)
    print 'Rdx: ' + hex(currentRdx)
    print 'Rbx: ' + hex(currentRbx)
    print 'Rsp: ' + hex(currentRSP)
    print 'Rbp: ' + hex(currentRBP)
    print 'Rip: ' + hex(currentRIP)
    print 'Rdi: ' + hex(currentRdi)
    print 'R8: ' + hex(currentR8)
    print 'R9: ' + hex(currentR9)
    print 'R10: ' + hex(currentR10)
    print 'R11: ' + hex(currentR11)
    print 'R12: ' + hex(currentR12)
    print 'R13: ' + hex(currentR13)
    print 'R14: ' + hex(currentR14)
    print 'R15: ' + hex(currentR15)

    print 'Floating Points:'
    print 'XMM0: ' + hex(currentXMM0High) + ' ' + hex(currentXMM0Low)
    print 'XMM1: ' + hex(currentXMM1High) + ' ' + hex(currentXMM1Low)
    print 'XMM2: ' + hex(currentXMM2High) + ' ' + hex(currentXMM2Low)
    print 'XMM3: ' + hex(currentXMM3High) + ' ' + hex(currentXMM3Low)
    print 'XMM4: ' + hex(currentXMM4High) + ' ' + hex(currentXMM4Low)
    print 'XMM5: ' + hex(currentXMM5High) + ' ' + hex(currentXMM5Low)
    print 'XMM6: ' + hex(currentXMM6High) + ' ' + hex(currentXMM6Low)
    print 'XMM7: ' + hex(currentXMM7High) + ' ' + hex(currentXMM7Low)
    print 'XMM8: ' + hex(currentXMM8High) + ' ' + hex(currentXMM8Low)
    print 'XMM9: ' + hex(currentXMM9High) + ' ' + hex(currentXMM9Low)
    print 'XMM10: ' + hex(currentXMM10High) + ' ' + hex(currentXMM10Low)
    print 'XMM11: ' + hex(currentXMM11High) + ' ' + hex(currentXMM11Low)
    print 'XMM12: ' + hex(currentXMM12High) + ' ' + hex(currentXMM12Low)
    print 'XMM13: ' + hex(currentXMM13High) + ' ' + hex(currentXMM13Low)
    print 'XMM14: ' + hex(currentXMM14High) + ' ' + hex(currentXMM14Low)
    print 'XMM15: ' + hex(currentXMM15High) + ' ' + hex(currentXMM15Low)

    print 'Breakpoints:'

    print 'DR0: ' + hex(dr0)
    print 'DR1: ' + hex(dr1)
    print 'DR2: ' + hex(dr2)
    print 'DR3: ' + hex(dr3)
    print 'DR6: ' + hex(dr6)
    print 'DR7: ' + hex(dr7)

    print 'Control Words: '
    print 'Mxcsr: ' + hex(MxCsr)
    print 'Context Flags: ' + hex(ContextFlags)
    print 'Control Word: ' + hex(ControlWord)
    print 'EFlags: ' + hex(EFlags)

    CloseHandle(threadhandletocheck)

def DetoruAddress(addressoffsettodetour):
    global infiniteloopaddress
    global raxregisterstorage
    written = c_ulonglong(0)
    threadarray = findAllThread(pid)
    for threadd in threadarray:
        threadHandle = OpenThread(THREAD_ACCESS_RIGHTS, False, threadd)
        #Wow64SuspendThread(threadHandle)
        SuspendThread(threadHandle)
        CloseHandle(threadHandle)

    functionaddress = baseaddress + addressoffsettodetour
    sizeofinstructiontostore = 15

    FunctionSpacee = VirtualAllocEx(processHandle, 0, 300, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
    infiniteloopaddress = FunctionSpacee
    RegisterStorage = VirtualAllocEx(processHandle, 0, 300, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
    raxregisterstorage = RegisterStorage
    packfunctionspace = struct.pack('q', FunctionSpacee)
    packedinfiniteloopjump = struct.pack('q', FunctionSpacee)
    packedregisterstorage = struct.pack('q', RegisterStorage)
    packedreturnaddress = struct.pack('q', (functionaddress + sizeofinstructiontostore))

    storebuffer = (c_ubyte * sizeofinstructiontostore)()

    ReadProcessMemory(processHandle, functionaddress, byref(storebuffer), sizeof(storebuffer), byref(written))

    jumpcode = "\x48\xA3"
    jumpcode += packedregisterstorage
    jumpcode += "\x48\xB8"
    jumpcode += packfunctionspace
    jumpcode += "\xFF\xE0\x90\x90\x90"

    WriteProcessMemory(processHandle, functionaddress, jumpcode, len(jumpcode), byref(written))

    #injectcode = "\x48\x89\xE0\x48\xA3"
    #injectcode += packedregisterstorage
    injectcode = "\x48\xB8"
    injectcode += packedinfiniteloopjump
    injectcode += "\xFF\xE0"

    WriteProcessMemory(processHandle, FunctionSpacee, injectcode, len(injectcode), byref(written))

    print "Infite loop address is " + hex(FunctionSpacee)
    print "Register storage is " + hex(RegisterStorage)
    print "Current debugging function address is " + hex(functionaddress)

    for threadd in threadarray:
        threadHandle = OpenThread(THREAD_ACCESS_RIGHTS, False, threadd)
        ResumeThread(threadHandle)
        CloseHandle(threadHandle)

def FindDebuggingThread():
    threadarray = findAllThread(pid)
    for threadd in threadarray:
        threadHandle = OpenThread(THREAD_ACCESS_RIGHTS, False, threadd)
        threadcontext = CONTEXT64()
        threadcontext.ContextFlags = (CONTEXT_ALL | CONTEXT_XSTATE)
        GetThreadContext(threadHandle, threadcontext)
        currentRIP = threadcontext.Rip
        #print currentRIP
        if(currentRIP == infiniteloopaddress or currentRIP == (infiniteloopaddress + 13) or currentRIP == (infiniteloopaddress + 15)):
            print "Debugging thread found!"
            CheckRegisters(threadHandle)
            break
        else:
            CloseHandle(threadHandle)


#PROGRAM FLOW
pid = get_client_pid("Wow.exe")
setProcessHandle(pid)
getBaseAddress()
print "Base address: " + str(baseaddress)
print "Size of mapped image: " + str(sizeofmodule)
if(baseaddress and sizeofmodule):
    askUserForAddress = raw_input("Offset to set breakpoint on (decimal, not hex): ")
    try:
        int(askUserForAddress)
    except:
        print "Offset is not a decimal number, try again"
        exit()
    else:
        remapsuccess = MemoryRemap()
        if remapsuccess is True:
            infiniteloopaddress = None
            DetoruAddress(int(askUserForAddress))
            while infiniteloopaddress != None:
                raw_input("Detour completed, type anything after client is frozen (breakpoint has been hit) to get registers")
                FindDebuggingThread()
            else:
                print "Address detour failed, couldnt get jump function address"