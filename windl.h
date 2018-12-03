// https://docs.microsoft.com/en-us/windows/desktop/psapi/enumerating-all-modules-for-a-process

#include <windows.h>
#include <process.h>
#include <psapi.h>

#include <string>
#include <vector>


using namespace std;

struct ModInfo {
  string name;
  void *start;
  size_t size;
};

static vector<ModInfo> modTable;

extern "C" {

typedef struct {
  const char *dli_fname;
  void *dli_fbase;
  const char *dli_sname;
  void *dli_saddr;
} Dl_info;

int dladdr(void *addr, Dl_info *info) {
  for (const auto &mod : modTable) {
    if (addr >= mod.start && addr < (void *)(((char *)mod.start) + mod.size)) {
      info->dli_fname = mod.name.c_str();
      info->dli_fbase = mod.start;
      info->dli_sname = NULL;
      info->dli_saddr = NULL;
      return 1;
    }
  }
  return 0;
}

void *dlopen(const char *filename, int flags) {
  return (void *)LoadLibrary(filename);
}

void dlclose(void *) {}

void *dlsym(void *handle, const char *symbol) {
  return (void *)GetProcAddress((HMODULE)handle, symbol);
}

void dlrefresh() {
  static HMODULE hMods[1024];
  static DWORD cbNeeded;
  unsigned int i;

  if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods),
                         &cbNeeded)) {
    vector<ModInfo> table;
    size_t modCount = (cbNeeded / sizeof(HMODULE));
    table.reserve(modCount);
    for (i = 0; i < modCount; ++i) {
      char name[MAX_PATH] = {0};
      if (GetModuleFileNameA(hMods[i], name, sizeof(name) / sizeof(char))) {
        MODULEINFO info;
        if (GetModuleInformation(GetCurrentProcess(), hMods[i], &info,
                                 sizeof(info))) {
          ModInfo mod = {name, info.lpBaseOfDll, info.SizeOfImage};
          table.push_back(mod);
        }
      }
    }
    modTable = table;
  }
}

#define RTLD_LAZY 0
#define RTLD_NOW 1
}
