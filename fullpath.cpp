#include <windows.h>
#include <WinIoCtl.h>

#include <Strsafe.h>
#include <string.h>
#include <stdio.h>

int
wmain(int argc, wchar_t** argv)
{
    wchar_t *buf;
    size_t szbuf = 32000;

    buf = new wchar_t[szbuf];

    for (int i = 1; i < argc; ++i) {
        wchar_t *arg = argv[i];
        DWORD r = GetFullPathNameW(arg, szbuf, buf, NULL);
        if (r == 0) {
            printf("GetFullPathNameW failed; error %d\n", GetLastError());
        } else if (r >= szbuf) {
            printf("GetFullPathNameW wants %d chars!\n", r);
        } else {
            printf("%S => %S\n", arg, buf);
        }
    }

    delete [] buf;
}
