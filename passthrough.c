#include <stdint.h>
#include <winfsp/winfsp.h>                        // (1)
#include "9pc.h"

#define PROGNAME            "9pfs"

typedef struct {
  FSP_FILE_SYSTEM *FileSystem;
  SOCKET socket;
  uint32_t rootfid;
  char *addr;
  char *port;
  uint32_t nextfid; /* might not always be top if we free one */
  uint32_t topfid; /* if topfid != nextfid make it so */
} NPFS;

typedef struct {
  uint32_t fid;
  Stat stat;
  PVOID dirbuf;
  uint8_t isdir;
  uint64_t length;
} NPFS_FILE_CONTEXT;

static
NTSTATUS SvcStart(FSP_SERVICE *Service, ULONG argc, PWSTR *argv)    // (2)
{
#define argtos(v)             if (arge > ++argp) v = *argp; else goto usage
#define argtol(v)             if (arge > ++argp) v = wcstol_deflt(*argp, v); else goto usage

  wchar_t **argp, **arge;
  PWSTR addr;
  PWSTR port;
  PWSTR DebugLogFile = 0;
  ULONG DebugFlags = 0;
  PWSTR VolumePrefix = 0;
  PWSTR PassThrough = 0;
  PWSTR MountPoint = 0;
  HANDLE DebugLogHandle = INVALID_HANDLE_VALUE;
  WCHAR PassThroughBuf[MAX_PATH];
  NPFS *npfs = 0;
  NTSTATUS Result;

  for (argp = argv + 1, arge = argv + argc; arge > argp; argp++)
  {
    if (L'-' != argp[0][0])
      break;
    switch (argp[0][1])
    {
    case L'?':
      goto usage;
    case L'd':
      argtol(DebugFlags);
      break;
    case L'D':
      argtos(DebugLogFile);
      break;
    case L'm':
      argtos(MountPoint);
      break;
    case L'p':
      argtos(PassThrough);
      break;
    case L'u':
      argtos(VolumePrefix);
      break;
    case L'P':
      argtos(port);
      break;
    case L'h':
      argtos(addr);
      break;
    default:
      goto usage;
    }
  }

  if (arge > argp)
    goto usage;

  if (0 == PassThrough && 0 != VolumePrefix)
  {
    PWSTR P;

    P = wcschr(VolumePrefix, L'\\');
    if (0 != P && L'\\' != P[1])
    {
      P = wcschr(P + 1, L'\\');
      if (0 != P &&
        (
        (L'A' <= P[1] && P[1] <= L'Z') ||
        (L'a' <= P[1] && P[1] <= L'z')
        ) &&
        L'$' == P[2])
      {
        StringCbPrintf(PassThroughBuf, sizeof PassThroughBuf, L"%c:%s", P[1], P + 3);
        PassThrough = PassThroughBuf;
      }
    }
  }

  if (0 == PassThrough || 0 == MountPoint)
    goto usage;

  EnableBackupRestorePrivileges();

  if (0 != DebugLogFile)
  {
    if (0 == wcscmp(L"-", DebugLogFile))
      DebugLogHandle = GetStdHandle(STD_ERROR_HANDLE);
    else
      DebugLogHandle = CreateFileW(
        DebugLogFile,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        0,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        0);
    if (INVALID_HANDLE_VALUE == DebugLogHandle)
    {
      fail(L"cannot open debug log file");
      goto usage;
    }

    FspDebugLogSetHandle(DebugLogHandle);
  }

  Result = PtfsCreate(PassThrough, VolumePrefix, MountPoint, DebugFlags, &Ptfs);
  if (!NT_SUCCESS(Result))
  {
    fail(L"cannot create file system");
    goto exit;
  }

  Result = FspFileSystemStartDispatcher(Ptfs->FileSystem, 0);
  if (!NT_SUCCESS(Result))
  {
    fail(L"cannot start file system");
    goto exit;
  }

  MountPoint = FspFileSystemMountPoint(Ptfs->FileSystem);

  info(L"%s%s%s -p %s -m %s",
    L"" PROGNAME,
    0 != VolumePrefix && L'\0' != VolumePrefix[0] ? L" -u " : L"",
      0 != VolumePrefix && L'\0' != VolumePrefix[0] ? VolumePrefix : L"",
    PassThrough,
    MountPoint);

  Service->UserContext = Ptfs;
  Result = STATUS_SUCCESS;

exit:
  if (!NT_SUCCESS(Result) && 0 != Ptfs)
    PtfsDelete(Ptfs);

  return Result;

usage:
  static wchar_t usage[] = L""
    "usage: %s OPTIONS\n"
    "\n"
    "options:\n"
    "  -d DebugFlags     [-1: enable all debug logs]\n"
    "  -D DebugLogFile   [file path; use - for stderr]\n"
    "  -u \\Server\\Share  [UNC prefix (single backslash)]\n"
    "  -p Directory    [directory to expose as pass through file system]\n"
    "  -m MountPoint     [X:|*|directory]\n";

  fail(usage, L"" PROGNAME);

  return STATUS_UNSUCCESSFUL;

#undef argtos
#undef argtol
}

static
NTSTATUS SvcStop(FSP_SERVICE *Service)                  // (3)
{
  return STATUS_NOT_IMPLEMENTED;
}

int wmain(int argc, wchar_t **argv)
{
  if (!NT_SUCCESS(FspLoad(0)))
    return ERROR_DELAY_LOAD_FAILED;
  return FspServiceRun(L"" PROGNAME, SvcStart, SvcStop, 0);       // (4)
}
