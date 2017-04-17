#include <vector>
#include <tuple>
#include <fstream>
#include "Windows.h"
#include <psapi.h>
#include <vector>

using namespace std;

namespace {
  typedef void(*callable)(void*);
  typedef tuple<void*, size_t> MyTuple;
  constexpr DWORD invocation_interval_ms = 15 * 1000;
  constexpr size_t stack_size = 0x10000;

  struct VersionToOffset {
    WORD file_version[4];
    uint32_t relative_offset;
  };

  /*
   * See https://changewindows.org/ for a detailed Windows 10 release history,
   * including updates to milestone releases.  A new build of the "mshtml.dll"
   * file has not been included with every update.
   */

  vector<VersionToOffset> mshtml_gadget_offset_map = {
    // Windows 10 Creators Update (Build v10.0.15063.138 as of Apr 11, 2017)
    {    11,     0, 15063,   138, 0x00585068 },
    // Windows 10 Creators Update (Build v10.0.15063.0 as of Mar 20, 2017)
    {    11,     0, 15063,     0, 0x00585098 },
    // Windows 10 Anniversary Update (Build v10.0.14393.953 as of Mar 14, 2017)
    {    11,     0, 14393,   953, 0x003CBD4D },
    // The default ROP gadget offset (for Windows v8.1?)
    {     0,     0,     0,     0, 0x006D55DD }
  };

  struct SetupConfiguration {
    uint32_t initialized;
    void* setup_address;
    uint32_t setup_length;
    void* VirtualProtectEx;
    void* WaitForSingleObjectEx;
    void* CreateWaitableTimer;
    void* SetWaitableTimer;
    void* MessageBox;
    void* tramp_addr;
    void* sleep_handle;
    uint32_t interval;
    void* target;
    uint8_t shadow[8];
  };

  struct StackTrampoline {
    void* VirtualProtectEx;
    void* return_address;
    void* current_process;
    void* address;
    uint32_t size;
    uint32_t protections;
    void* old_protections_ptr;
    uint32_t old_protections;
    void* setup_config;
  };

  struct Workspace {
    SetupConfiguration config;
    uint8_t stack[stack_size];
    StackTrampoline tramp;
  };
}

Workspace& allocate_workspace() {
  auto result = VirtualAllocEx(GetCurrentProcess(), nullptr, sizeof(Workspace), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!result) throw runtime_error("[-] Couldn't VirtualAllocEx: " + GetLastError());
  RtlSecureZeroMemory(result, sizeof(Workspace));
  return *static_cast<Workspace*>(result);
}

MyTuple allocate_pic(const string& filename) {
  
  fstream file_stream{ filename, fstream::in | fstream::ate | fstream::binary };
  if (!file_stream) throw runtime_error("[-] Couldn't open " + filename);
  auto pic_size = static_cast<size_t>(file_stream.tellg());
  file_stream.seekg(0, fstream::beg);
  auto pic = VirtualAllocEx(GetCurrentProcess(), nullptr, pic_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!pic) throw runtime_error("[-] Couldn't VirtualAllocEx: " + GetLastError());
  file_stream.read(static_cast<char*>(pic), pic_size);
  file_stream.close();
  DWORD old_protection;
  auto prot_result = VirtualProtectEx(GetCurrentProcess(), pic, pic_size, PAGE_EXECUTE_READ, &old_protection);
  if (!prot_result) throw runtime_error("[-] Couldn't VirtualProtectEx: " + GetLastError());
  return MyTuple(pic, pic_size);
}

uint32_t get_mshtml_gadget_relative_offset(const char *mshtml_filename) {
  DWORD version_handle;
  auto version_info_size = GetFileVersionInfoSizeA(mshtml_filename, &version_handle);
  if (version_info_size == 0) throw runtime_error("[-] Couldn't GetFileVersionInfoSize: " + GetLastError());

  vector<char> version_data(version_info_size);
  auto result = GetFileVersionInfoA(mshtml_filename, version_handle, version_info_size, &version_data[0]);
  if (!result) {
      throw runtime_error("[-] Couldn't GetFileVersionInfo: " + GetLastError());
  }

  LPBYTE version_info_buffer;
  UINT version_info_buffer_size;
  result = VerQueryValueA(&version_data[0], "\\", reinterpret_cast<VOID FAR* FAR*>(&version_info_buffer), &version_info_buffer_size);
  if (!result) {
      throw runtime_error("[-] Couldn't VerQueryValue: " + GetLastError());
  }

  auto *version_info = reinterpret_cast<VS_FIXEDFILEINFO *>(version_info_buffer);
  WORD unpacked_file_version_words[4] = {
    (version_info->dwFileVersionMS >> 16) & 0xffff,
    (version_info->dwFileVersionMS >> 0) & 0xffff,
    (version_info->dwFileVersionLS >> 16) & 0xffff,
    (version_info->dwFileVersionLS >> 0) & 0xffff };
  auto unpacked_file_version = *reinterpret_cast<DWORDLONG *>(unpacked_file_version_words);

  printf("[ ] Found %s version %d.%d.%d.%d.\n",
    mshtml_filename,
    unpacked_file_version_words[0],
    unpacked_file_version_words[1],
    unpacked_file_version_words[2],
    unpacked_file_version_words[3]);

  uint32_t relative_offset = 0;
  auto using_default = false;
  auto entry_num = 0;
  while (relative_offset == 0) {
    auto* version_entry = &mshtml_gadget_offset_map[entry_num];
    if (*reinterpret_cast<DWORDLONG *>(version_entry->file_version) == unpacked_file_version
      || *reinterpret_cast<DWORDLONG *>(version_entry->file_version) == 0)
      relative_offset = version_entry->relative_offset;
      using_default = *reinterpret_cast<DWORDLONG *>(version_entry->file_version) == 0;
    ++entry_num;
  }

  if (using_default) {
    printf("[*] WARNING: Unrecognized version, so using default relative offset.\n");
  }
  printf("[ ] %s ROP gadget is at relative offset 0x%p.\n", mshtml_filename, reinterpret_cast<void *>(relative_offset));

  return relative_offset;
}

void* get_mshtml_gadget() {
  auto mshtml_filename = "mshtml.dll";
  printf("[ ] Loading %s.\n", mshtml_filename);
  auto mshtml_gadget_offset = get_mshtml_gadget_relative_offset(mshtml_filename);
  auto mshtml_base = reinterpret_cast<uint8_t*>(LoadLibraryA(mshtml_filename));
  if (!mshtml_base) throw runtime_error("[-] Couldn't LoadLibrary: " + GetLastError());

  printf("[+] Loaded %s into memory at 0x%p.\n", mshtml_filename, mshtml_base);
  return mshtml_base + mshtml_gadget_offset;
}

void* get_gadget(bool use_mshtml, const string& gadget_pic_path) {
  void* memory;
  if (use_mshtml) {
    memory = get_mshtml_gadget();
  } else {
    printf("[ ] Allocating memory for %s.\n", gadget_pic_path.c_str());
    size_t size;
    tie(memory, size) = allocate_pic(gadget_pic_path);
    printf("[ ] Allocated %u bytes for gadget PIC.\n", size);
  }
  return memory;
}

void launch(const string& setup_pic_path, const string& gadget_pic_path) {
  printf("[ ] Allocating executable memory for %s.\n", setup_pic_path.c_str());
  void* setup_memory; size_t setup_size;
  tie(setup_memory, setup_size) = allocate_pic(setup_pic_path);
  printf("[+] Allocated %d bytes for PIC.\n", setup_size);

  auto use_mshtml{ true };
  printf("[ ] Configuring ROP gadget.\n");
  auto gadget_memory = get_gadget(use_mshtml, gadget_pic_path);
  printf("[+] ROP gadget configured.\n");

  printf("[ ] Allocating read/write memory for config, stack, and trampoline.\n");
  auto& scratch_memory = allocate_workspace();
  auto& config = scratch_memory.config;
  auto& tramp = scratch_memory.tramp;
  printf("[+] Allocated %u bytes for scratch memory.\n", sizeof(scratch_memory));

  printf("[ ] Building stack trampoline.\n");
  tramp.old_protections_ptr = &tramp.old_protections;
  tramp.protections = PAGE_EXECUTE_READ;
  tramp.current_process = GetCurrentProcess();
  tramp.VirtualProtectEx = VirtualProtectEx;
  tramp.size = static_cast<uint32_t>(setup_size);
  tramp.address = setup_memory;
  tramp.return_address = setup_memory;
  tramp.setup_config = &config;
  printf("[+] Stack trampoline built.\n");

  printf("[ ] Building configuration.\n");
  config.setup_address = setup_memory;
  config.setup_length = static_cast<uint32_t>(setup_size);
  config.VirtualProtectEx = VirtualProtectEx;
  config.WaitForSingleObjectEx = WaitForSingleObjectEx;
  config.CreateWaitableTimer = CreateWaitableTimerW;
  config.SetWaitableTimer = SetWaitableTimer;
  config.MessageBox = MessageBoxA;
  config.tramp_addr = &tramp;
  config.interval = invocation_interval_ms;
  config.target = gadget_memory;
  printf("[+] Configuration built.\n");

  printf("[+] Success!\n");
  printf("    ================================\n");
  printf("    Gargoyle PIC @ -----> 0x%p\n", setup_memory);
  printf("    ROP gadget @ -------> 0x%p\n", gadget_memory);
  printf("    Configuration @ ----> 0x%p\n", &scratch_memory.config);
  printf("    Top of stack @ -----> 0x%p\n", &scratch_memory.stack);
  printf("    Bottom of stack @ --> 0x%p\n", &scratch_memory.stack[stack_size-1]);
  printf("    Stack trampoline @ -> 0x%p\n", &scratch_memory.tramp);

  reinterpret_cast<callable>(setup_memory)(&config);
}

int main() {
  try {
    launch("setup.pic", "gadget.pic");
  } catch (exception& e) {
    printf("%s\n", e.what());
  }
}
