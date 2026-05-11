#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <Windows.h>

using namespace std;

namespace {
  using PicEntry = void (*)(void*);
  using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
  constexpr DWORD invocation_interval_ms = 15 * 1000;
  constexpr size_t reentry_callback_offset = 16;

#ifndef IMAGE_FILE_MACHINE_ARM64EC
  constexpr USHORT IMAGE_FILE_MACHINE_ARM64EC = 0xA641;
#endif

  struct X64Configuration {
    uint64_t initialized;
    void* setup_address;
    uint64_t setup_length;
    void* reentry_wait;
    void* reentry_callback;
    void* VirtualProtectEx;
    void* SleepEx;
    void* CreateWaitableTimerW;
    void* SetWaitableTimer;
    void* MessageBoxA;
    void* timer_handle;
    int64_t due_time;
    uint32_t interval;
    uint32_t old_protection;
  };

  static_assert(sizeof(void*) == 8, "GargoyleX64 must be built as a 64-bit target.");
  static_assert(offsetof(X64Configuration, initialized) == 0x00);
  static_assert(offsetof(X64Configuration, setup_address) == 0x08);
  static_assert(offsetof(X64Configuration, setup_length) == 0x10);
  static_assert(offsetof(X64Configuration, reentry_wait) == 0x18);
  static_assert(offsetof(X64Configuration, reentry_callback) == 0x20);
  static_assert(offsetof(X64Configuration, VirtualProtectEx) == 0x28);
  static_assert(offsetof(X64Configuration, SleepEx) == 0x30);
  static_assert(offsetof(X64Configuration, CreateWaitableTimerW) == 0x38);
  static_assert(offsetof(X64Configuration, SetWaitableTimer) == 0x40);
  static_assert(offsetof(X64Configuration, MessageBoxA) == 0x48);
  static_assert(offsetof(X64Configuration, timer_handle) == 0x50);
  static_assert(offsetof(X64Configuration, due_time) == 0x58);
  static_assert(offsetof(X64Configuration, interval) == 0x60);
  static_assert(offsetof(X64Configuration, old_protection) == 0x64);

  constexpr USHORT compiled_machine() {
#if defined(_M_IX86)
    return IMAGE_FILE_MACHINE_I386;
#elif defined(_M_X64)
    return IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_ARM64EC)
    return IMAGE_FILE_MACHINE_ARM64EC;
#elif defined(_M_ARM64)
    return IMAGE_FILE_MACHINE_ARM64;
#else
    return IMAGE_FILE_MACHINE_UNKNOWN;
#endif
  }

  const char* machine_name(USHORT machine) {
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386:
      return "x86";
    case IMAGE_FILE_MACHINE_AMD64:
      return "x64";
    case IMAGE_FILE_MACHINE_ARM64:
      return "arm64";
    case IMAGE_FILE_MACHINE_ARM64EC:
      return "arm64ec";
    case IMAGE_FILE_MACHINE_UNKNOWN:
      return "unknown";
    default:
      return "other";
    }
  }

  USHORT native_machine_from_system_info() {
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    switch (info.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_INTEL:
      return IMAGE_FILE_MACHINE_I386;
    case PROCESSOR_ARCHITECTURE_AMD64:
      return IMAGE_FILE_MACHINE_AMD64;
    case PROCESSOR_ARCHITECTURE_ARM64:
      return IMAGE_FILE_MACHINE_ARM64;
    default:
      return IMAGE_FILE_MACHINE_UNKNOWN;
    }
  }

  void print_architecture_report() {
    auto process_machine = compiled_machine();
    auto native_machine = native_machine_from_system_info();
    auto used_is_wow64_process2 = false;

    const auto kernel32 = GetModuleHandleW(L"kernel32.dll");
    const auto is_wow64_process2 = kernel32
      ? reinterpret_cast<IsWow64Process2Fn>(GetProcAddress(kernel32, "IsWow64Process2"))
      : nullptr;
    if (is_wow64_process2) {
      USHORT reported_process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
      USHORT reported_native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
      if (is_wow64_process2(GetCurrentProcess(), &reported_process_machine, &reported_native_machine)) {
        used_is_wow64_process2 = true;
        if (reported_process_machine != IMAGE_FILE_MACHINE_UNKNOWN) {
          process_machine = reported_process_machine;
        }
        if (reported_native_machine != IMAGE_FILE_MACHINE_UNKNOWN) {
          native_machine = reported_native_machine;
        }
      }
    }

    printf("[+] Architecture report.\n");
    printf("platform=%s\n", machine_name(compiled_machine()));
    printf("machine=0x%04hx\n", compiled_machine());
    printf("pointer_bits=%zu\n", sizeof(void*) * 8);
    printf("    Compiled machine @ ----> 0x%04hx (%s)\n", compiled_machine(), machine_name(compiled_machine()));
    printf("    Process machine @ -----> 0x%04hx (%s)\n", process_machine, machine_name(process_machine));
    printf("    Native machine @ ------> 0x%04hx (%s)\n", native_machine, machine_name(native_machine));
    printf("    IsWow64Process2 @ ----> %s\n", used_is_wow64_process2 ? "available" : "unavailable");
  }

  bool has_argument(int argc, char** argv, const char* value) {
    for (auto index = 1; index < argc; ++index) {
      if (strcmp(argv[index], value) == 0) {
        return true;
      }
    }
    return false;
  }

  vector<uint8_t> read_binary(const string& filename) {
    fstream stream{ filename, fstream::in | fstream::ate | fstream::binary };
    if (!stream) {
      throw runtime_error("[-] Couldn't open \"" + filename + "\".");
    }

    const auto size = static_cast<size_t>(stream.tellg());
    stream.seekg(0, fstream::beg);

    auto result = vector<uint8_t>(size);
    stream.read(reinterpret_cast<char*>(result.data()), result.size());
    if (!stream) {
      throw runtime_error("[-] Couldn't read \"" + filename + "\".");
    }
    return result;
  }

  void* resolve_export(const wchar_t* module_name, const char* export_name) {
    auto module = GetModuleHandleW(module_name);
    if (!module) {
      module = LoadLibraryW(module_name);
    }
    if (!module) {
      throw runtime_error("[-] Couldn't load module.");
    }

    const auto address = GetProcAddress(module, export_name);
    if (!address) {
      throw runtime_error("[-] Couldn't GetProcAddress.");
    }
    return reinterpret_cast<void*>(address);
  }

  void* allocate_pic(const string& filename, size_t& pic_size) {
    const auto bytes = read_binary(filename);
    pic_size = bytes.size();

    const auto memory = VirtualAlloc(nullptr, pic_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory) {
      throw runtime_error("[-] Couldn't VirtualAlloc.");
    }

    memcpy(memory, bytes.data(), bytes.size());

    DWORD old_protection;
    const auto protected_memory = VirtualProtect(memory, pic_size, PAGE_EXECUTE_READ, &old_protection);
    if (!protected_memory) {
      throw runtime_error("[-] Couldn't VirtualProtect.");
    }
    return memory;
  }
}

void launch(const string& setup_pic_path) {
  printf("[ ] Loading x64 setup PIC from \"%s\".\n", setup_pic_path.c_str());
  size_t setup_size;
  const auto setup_memory = allocate_pic(setup_pic_path, setup_size);
  printf("[+] Loaded %zu bytes of x64 PIC.\n", setup_size);

  const auto reentry_pic_path = "reentry_x64.pic";
  printf("[ ] Loading x64 re-entry PIC from \"%s\".\n", reentry_pic_path);
  size_t reentry_size;
  const auto reentry_memory = allocate_pic(reentry_pic_path, reentry_size);
  const auto reentry_callback =
    static_cast<void*>(static_cast<uint8_t*>(reentry_memory) + reentry_callback_offset);
  printf("[+] Loaded %zu bytes of x64 re-entry PIC.\n", reentry_size);

  auto config = X64Configuration{};
  config.setup_address = setup_memory;
  config.setup_length = setup_size;
  config.reentry_wait = reentry_memory;
  config.reentry_callback = reentry_callback;
  config.VirtualProtectEx = resolve_export(L"kernel32.dll", "VirtualProtectEx");
  config.SleepEx = resolve_export(L"kernel32.dll", "SleepEx");
  config.CreateWaitableTimerW = resolve_export(L"kernel32.dll", "CreateWaitableTimerW");
  config.SetWaitableTimer = resolve_export(L"kernel32.dll", "SetWaitableTimer");
  config.MessageBoxA = resolve_export(L"user32.dll", "MessageBoxA");
  config.due_time = -static_cast<int64_t>(invocation_interval_ms) * 10000;
  config.interval = invocation_interval_ms;

  printf("[+] x64 timer/APC prototype configured.\n");
  printf("    ================================\n");
  printf("    Gargoyle x64 PIC @ ----> 0x%p\n", setup_memory);
  printf("    x64 re-entry PIC @ ----> 0x%p\n", reentry_memory);
  printf("    x64 APC callback @ ---> 0x%p\n", reentry_callback);
  printf("    Configuration @ -------> 0x%p\n", &config);
  printf("    VirtualProtectEx @ ----> 0x%p\n", config.VirtualProtectEx);
  printf("    SleepEx @ ------------> 0x%p\n", config.SleepEx);
  printf("    CreateWaitableTimerW @  0x%p\n", config.CreateWaitableTimerW);
  printf("    SetWaitableTimer @ ---> 0x%p\n", config.SetWaitableTimer);
  printf("    MessageBoxA @ --------> 0x%p\n", config.MessageBoxA);
  printf("    Timer period @ -------> %lu ms\n", invocation_interval_ms);
  printf("[ ] Entering benign x64 PIC payload loop.\n");

  reinterpret_cast<PicEntry>(setup_memory)(&config);

  printf("[-] x64 PIC returned unexpectedly.\n");
}

int main(int argc, char** argv) {
  setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    if (has_argument(argc, argv, "--architecture-report")) {
      print_architecture_report();
      return 0;
    }
    launch("setup_x64.pic");
  } catch (const exception& e) {
    printf("%s\n", e.what());
    return 1;
  }
  return 0;
}
