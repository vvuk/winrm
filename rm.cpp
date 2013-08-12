/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* Written in 2011, 2012 by John Ford <jhford@mozilla.com>
 * More hacking by Vladimir Vukicevic <vladimir@pobox.com>
 *
 * This program is a replacement for the Posix 'rm' utility implemented as
 * a native Windows win32 application.  Build using accompanying Makefile
 *    make
 * or by running
 *    cl rm.cpp
 */
#include <windows.h>
#include <WinIoCtl.h>

#include <Strsafe.h>
#include <string.h>
#include <stdio.h>

#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003
#endif

#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK 0xA000000C
#endif

static bool hasSymlinks = false;
static bool hasRestoreBackupPrivilege = false;

static bool deleteJunctions = false;
static bool quiet = false;
static bool verbose = false;
static bool force = false;
static bool recurse = false;


bool
EnsureBackupRestorePrivilege()
{
    if (hasRestoreBackupPrivilege)
        return true;

    HANDLE token;
    TOKEN_PRIVILEGES tp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token);
    LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(token);

    hasRestoreBackupPrivilege = true;
    return true;
}

/* TODO:
 *   -should the wow64fsredirection stuff be applicable to the whole app
 *    or only per empty_directory invocation?
 *   -support simple unix-style paths (i.e. map /c/dir1/file1 to c:\\dir1\\file1) 
 *   -return non-zero if no files are deleted and -f isn't specified
 *   -multi-thread deletions
 */

/* This function takes an errNum, filename of the file being operated on and
 * a stdio file handle to the file where output should be printed
 */
void
print_error(DWORD errNum, wchar_t* filename, FILE* fhandle, wchar_t* prefix = NULL) {
    wchar_t* msg;
    FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            errNum,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPWSTR) &msg,
            0, NULL);
    if (!prefix)
        prefix = L"";
    fwprintf(fhandle, L"%ws\"%ws\": %ws", prefix, filename, msg);
}

/*
 * Deal with symlinks and reparse points on directories.  Returns TRUE and sets rv
 * if it handled the deletion.
 *
 * Should we ever do multithreaded deletion, this is not thread safe!
 */
BOOL
handle_del_reparse_point(wchar_t *name, BOOL *rv)
{
    if ((GetFileAttributesW(name) & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
        return FALSE;

    if (!(hasSymlinks || deleteJunctions))
        return FALSE;

    HANDLE hDir = CreateFile(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (!hDir) {
        fwprintf(stderr, L"Failed to open directory '%ws': 0x%08x\n", name, GetLastError());
        *rv = FALSE;
        return TRUE;
    }

    // XXX not thread safe
    static REPARSE_GUID_DATA_BUFFER *rd = NULL;
    if (!rd) {
        rd = (REPARSE_GUID_DATA_BUFFER*) malloc(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    }

    DWORD dwRet;

    if (!DeviceIoControl(hDir, FSCTL_GET_REPARSE_POINT, NULL, 0,
                         rd, MAXIMUM_REPARSE_DATA_BUFFER_SIZE,
                         &dwRet, NULL))
    {
        fwprintf(stderr, L"DeviceIoControl failed for directory '%ws': 0x%08x\n", name, GetLastError());
        *rv = FALSE;
        return TRUE;
    }

    if (rd->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
        // This is a symlink; we must hand it to del_directory directly
        // to delete the symlink (which is done by deleting the directory normally).
        CloseHandle(hDir);

        *rv = RemoveDirectoryW(name);
        if (!*rv) {
            if (!quiet) {
                print_error(GetLastError(), name, stderr);
            }
        }
        if (verbose) {
            fwprintf(stdout, L"deleted symlink directory \"%ws\"\n", name);
        }
        return TRUE;
    }

    // close this, because it was opened for read only.  If we need
    // to munge reparse points, we're going to need to open for write.
    CloseHandle(hDir);

    if (rd->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT &&
        deleteJunctions)
    {
        DWORD tag = rd->ReparseTag;
        GUID gu = rd->ReparseGuid;
        
        if (!EnsureBackupRestorePrivilege()) {
            fwprintf(stderr, L"Internal error: couldn't adjust token privileges to delete junction");
            return FALSE;
        }

        HANDLE hDir = CreateFile(name, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
                                 NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (!hDir) {
            fwprintf(stderr, L"Failed to open directory '%ws': 0x%08x\n", name, GetLastError());
            *rv = FALSE;
            return TRUE;
        }

        memset(rd, 0, MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
        rd->ReparseTag = tag;
        rd->ReparseGuid = gu;
        BOOL ok = DeviceIoControl(hDir, FSCTL_DELETE_REPARSE_POINT, rd,
                                  REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, 0, &dwRet, NULL);

        CloseHandle(hDir);

        if (!ok) {
            fwprintf(stderr, L"DeviceIoControl failed to delete junction '%ws': 0x%08x\n", name, GetLastError());
            *rv = FALSE;
            return TRUE;
        }

        // if we deleted a junction, the last step is to remove the (now empty, normal) directory itself
        *rv = RemoveDirectoryW(name);
        return TRUE;
    }

    return FALSE;
}

/* Remove an empty directory.  This will fail if there are still files or
 * other directories in the directory specified by name
 */
BOOL
del_directory(wchar_t* name)
{
    BOOL rv = TRUE;
    if (verbose) {
        fwprintf(stdout, L"deleting directory \"%ws\"\n", name);
    }

    if (handle_del_reparse_point(name, &rv))
        return rv;

    BOOL delStatus = RemoveDirectoryW(name);
    if (!delStatus) {
        rv = FALSE;
        if (!quiet) {
            print_error(GetLastError(), name, stderr);
        }
    }
    if (verbose) {
        fwprintf(stdout, L"deleted directory \"%ws\"\n", name);
    }
    return rv;
}

/* Remove a file.  If force is true, read only and system file system
 * attributes are cleared before deleting the file
 */
BOOL
del_file(wchar_t* name)
{
    BOOL rv = TRUE;
    if (force) {
        DWORD fileAttr = GetFileAttributesW(name);
        if (fileAttr == INVALID_FILE_ATTRIBUTES) {
            if (!quiet) {
                print_error(GetLastError(), name, stderr, L"error getting file attributes for ");
            }
            // Hmm, should I still try to delete the file?
            return FALSE;
        }
        if (fileAttr & FILE_ATTRIBUTE_DIRECTORY) {
            if (!quiet) {
                fwprintf(stderr, L"%ws is a directory, not a file\n", name);
                rv = FALSE;
            }
        }
        // Should really only have one SetFileAttributes
        if (fileAttr & FILE_ATTRIBUTE_SYSTEM ||
            fileAttr & FILE_ATTRIBUTE_READONLY) {
            DWORD toSet = FILE_ATTRIBUTE_NORMAL;
            if (verbose) {
                wprintf(L"changing \"%ws\" file attributes to be removable\n", name);
            }
            DWORD setAttrStatus = SetFileAttributesW(name, toSet);
            if (!setAttrStatus){
                rv = FALSE;
                if (!quiet) {
                    print_error(setAttrStatus, name, stderr);
                }
            }
        }
    }
    if (verbose) {
        fwprintf(stdout, L"deleting \"%ws\"\n", name);
    }
    BOOL delStatus = DeleteFileW(name);
    if (!delStatus) {
        rv = FALSE;
        if (!quiet)
            print_error(GetLastError(), name, stderr);
    } else if (verbose) {
        fwprintf(stdout, L"deleted \"%ws\"\n", name);
    }
    return rv;
}

/* This function will recursively remove all files in a directory
 * then the directory itself.
 */
BOOL
empty_directory(wchar_t* name)
{
    BOOL rv = TRUE;
    DWORD ffStatus;
    WIN32_FIND_DATAW findFileData;
    // TODO: Don't waste so much memory!
    wchar_t dir[MAX_PATH];
    HANDLE hFind = INVALID_HANDLE_VALUE;
	// Used while disabling Wow64 FS Redirection
	//Unused for now PVOID* wow64value = NULL;

    /* If we have symlinks, we need to check if "name" is a symlink
     * first.  If so, we need to delete it instead.
     *
     * Likewise if -j was passed, do the same for junctions
     */
    if (handle_del_reparse_point(name, &rv))
        return rv;

    /* without a trailing \*, the listing for "c:\windows" would show info
     * for "c:\windows", not files *inside* of "c:\windows"
     */
    StringCchCopyW(dir, MAX_PATH, name); // TODO: Check return
    StringCchCatW(dir, MAX_PATH, L"\\*");

    /* We don't know what's going on, but Wow64 redirection
     * is not working quite right.  Since nothing we have should
     * be in a location that needs Wow64, we should be fine to
     * ignore it
     */
    //Wow64DisableWow64FsRedirection(wow64value);

    hFind = FindFirstFileW(dir, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        rv = FALSE;
        if (!quiet) {
            print_error(GetLastError(), name, stderr);
        }
        return rv;
    }

    do { 
        wchar_t fullName[MAX_PATH];
        StringCchCopyW(fullName, MAX_PATH, name);
        StringCchCatW(fullName, MAX_PATH, L"\\");
        StringCchCatW(fullName, MAX_PATH, findFileData.cFileName);
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // don't try to do anything with "." or ".."
            if (wcscmp(L".", findFileData.cFileName) == 0 ||
                wcscmp(L"..", findFileData.cFileName) == 0)
            {
                continue;
            }

            
            if (!empty_directory(fullName)){
                rv = FALSE;
            }
        } else {
            if (!del_file(fullName)) {
                rv = FALSE;
            }
        }
    } while (FindNextFileW(hFind, &findFileData) != 0);

    /* if (!Wow64RevertWow64FsRedirection(wow64value)) {
     *    if (!quiet) {
     *        fwprintf(stderr, L"Error restoring Wow64 FS Redirection\n");
     *    }
     *    return FALSE;
     * }
     */

    ffStatus = GetLastError();
    if (ffStatus != ERROR_NO_MORE_FILES) {
        print_error(ffStatus, findFileData.cFileName, stderr);
        rv = FALSE;
    }

    FindClose(hFind);

    del_directory(name);

    return rv;

}

/* This function is used to delete a file or directory specified by the
 * 'name' variable.  The type of 'name' is figured out.  If the recurse
 * option is TRUE, directories will be recursively emptied then deleted.
 * If force is TRUE, file attributes will be changed to allow the program
 * to delete the file.  The verbose option will cause non-fatal error messages
 * to print to stderr.  The quiet option will supress all but fatal 
 * error messages
 */
BOOL
del(wchar_t* name)
{
    DWORD fileAttr = GetFileAttributesW(name);
    if (fileAttr == INVALID_FILE_ATTRIBUTES) {
        DWORD err = GetLastError();
        if (force && (err == ERROR_INVALID_NAME ||
                      err == ERROR_FILE_NOT_FOUND ||
                      err == ERROR_PATH_NOT_FOUND))
        {
            // it's already deleted; nothing to do
            return TRUE;
        }

        print_error(err, name, stderr, L"cannot get attributes for ");
        return FALSE;
    }

    if (fileAttr & FILE_ATTRIBUTE_REPARSE_POINT) {
        BOOL rv = TRUE;
        BOOL handled = handle_del_reparse_point(name, &rv);
        if (handled)
            return rv;
    }

    if (fileAttr & FILE_ATTRIBUTE_DIRECTORY) {
        if (recurse) {
            return empty_directory(name);
        }

        fwprintf(stderr, L"cannot remove directory '%ws': Is a directory\n", name);
        return FALSE;
    }

    return del_file(name);
}

/* This struct is used by the command line parser */
struct node {
    node *next;
    wchar_t* data;
};

int
wmain(int argc, wchar_t** argv)
{
    int exitCode = 0;
    int i, j;
    BOOL onlyFiles = FALSE;
    struct node *previous = NULL;
    struct node *start = NULL;
    for (i = 1 ; i < argc ; i++) {
        if (wcscmp(argv[i], L"--") == 0) {
            /* Once we've seen '--' as an arg in the argv,
             * we want to interpret everything after that point
             * as a file
             */
            onlyFiles = TRUE;
        } else if (!onlyFiles && argv[i][0] == L'-') {
            /* Before the -- appears (if ever), we assume that all
             * args starting with - are options.  If I wanted to do
             * full words, I would have a check for the second char
             * being another - in a case and use that case and wsccmp
             * to set the options.
             */
            for (j = 1 ; j < wcslen(argv[i]) ; j++) {
                switch(argv[i][j]){
                    case L'v':
                        verbose = TRUE;
                        break;
                    case L'q':
                        quiet = TRUE;
                        break;
                    case L'r':
                        recurse = TRUE;
                        break;
                    case L'f':
                        force = TRUE;
                        break;
                    case L'j':
                        deleteJunctions = true;
                        break;
                    default:
                        fwprintf(stderr, L"The option -%wc is not valid\n", argv[i][j]);
                        fwprintf(stderr, L"Valid options are: \n");
                        fwprintf(stderr, L" -v  Be verbose \n");
                        fwprintf(stderr, L" -q  Be quiet \n");
                        fwprintf(stderr, L" -r  Delete directories recursively \n");
                        fwprintf(stderr, L" -f  Force deletion \n");
                        fwprintf(stderr, L" -j  Delete junction points, don't recurse into them \n");
                        exitCode = 1;
                 }
            }
        } else {
            /* If there are no more options, or we are forcing the rest of the
             * args to be files, we add them to the linked list.  This list stores
             * args in reverse order to what is on the command line.
             */
            struct node *nextNode = (struct node *) malloc(sizeof(struct node));
            nextNode->data = argv[i];
            nextNode->next = previous;
            previous = nextNode;
            start = nextNode;
        }
    }
    if (verbose && quiet) {
        fwprintf(stderr, L"The -q (quiet) and -v (verbose) options are incompatible\n");
        exitCode = 1;
    }

    /* If we have symlinks on this OS (>= Vista), we need to check for them before
     * deleting directories.
     */
    hasSymlinks = (GetVersion() & 0xff) >= 0x06;

    /* If everything is good, its time to start deleting the files.
     * We do this by traversing the linked list, deleting the current
     * node then deleting the current node before moving to the next
     */
    if (!exitCode) {
        struct node* current = start;
        while (current != NULL){
            BOOL result = del(current->data);
            if (!result) {
                exitCode = 1;
            }
            struct node* cleanup = current;
            current = current->next;
            free(cleanup);
        }
    }

    return exitCode;
}

