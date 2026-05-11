#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include <Windows.h>

#ifndef IMAGE_FILE_MACHINE_ARM64EC
#define IMAGE_FILE_MACHINE_ARM64EC 0xA641
#endif

#if defined(_M_ARM64EC) && !defined(MEM_EXTENDED_PARAMETER_EC_CODE)
#define MEM_EXTENDED_PARAMETER_EC_CODE 0x00000040
#endif

namespace gargoyle_arm {
  using PicEntry = void (*)(void*);

  constexpr DWORD live_default_period_ms = 15 * 1000;
  constexpr DWORD headless_default_period_ms = 250;
  constexpr uint32_t default_rounds = 2;
  constexpr size_t reentry_callback_offset = 16;

  enum class RuntimeMode {
    live,
    headless,
    architecture_report,
  };

  struct RuntimeTraits {
    const char* display_name;
    const char* file_suffix;
    const char* setup_pic;
    const char* reentry_pic;
  };

  struct RuntimeOptions {
    RuntimeMode mode = RuntimeMode::live;
    uint32_t rounds = default_rounds;
    DWORD period_ms = live_default_period_ms;
    bool period_was_set = false;
    bool show_help = false;
  };

  struct ArmConfiguration {
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
    void* sleep_handle;
    int64_t due_time;
    uint32_t interval;
    uint32_t old_protection;
    uint32_t mode;
    uint32_t remaining_rounds;
    uint32_t completed_rounds;
    uint32_t callback_rounds;
  };

  static_assert(sizeof(void*) == 8, "Gargoyle ARM runtimes must be built as 64-bit targets.");
  static_assert(offsetof(ArmConfiguration, initialized) == 0x00);
  static_assert(offsetof(ArmConfiguration, setup_address) == 0x08);
  static_assert(offsetof(ArmConfiguration, setup_length) == 0x10);
  static_assert(offsetof(ArmConfiguration, reentry_wait) == 0x18);
  static_assert(offsetof(ArmConfiguration, reentry_callback) == 0x20);
  static_assert(offsetof(ArmConfiguration, VirtualProtectEx) == 0x28);
  static_assert(offsetof(ArmConfiguration, SleepEx) == 0x30);
  static_assert(offsetof(ArmConfiguration, CreateWaitableTimerW) == 0x38);
  static_assert(offsetof(ArmConfiguration, SetWaitableTimer) == 0x40);
  static_assert(offsetof(ArmConfiguration, MessageBoxA) == 0x48);
  static_assert(offsetof(ArmConfiguration, sleep_handle) == 0x50);
  static_assert(offsetof(ArmConfiguration, due_time) == 0x58);
  static_assert(offsetof(ArmConfiguration, interval) == 0x60);
  static_assert(offsetof(ArmConfiguration, old_protection) == 0x64);
  static_assert(offsetof(ArmConfiguration, mode) == 0x68);
  static_assert(offsetof(ArmConfiguration, remaining_rounds) == 0x6C);
  static_assert(offsetof(ArmConfiguration, completed_rounds) == 0x70);
  static_assert(offsetof(ArmConfiguration, callback_rounds) == 0x74);

  inline std::string win32_error(const std::string& operation, DWORD error = GetLastError()) {
    LPSTR message = nullptr;
    const auto chars = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr,
      error,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPSTR>(&message),
      0,
      nullptr
    );

    auto result = operation + " failed (GetLastError=" + std::to_string(error) + ")";
    if (chars != 0 && message != nullptr) {
      std::string formatted{ message, static_cast<size_t>(chars) };
      while (!formatted.empty() && (formatted.back() == '\r' || formatted.back() == '\n')) {
        formatted.pop_back();
      }
      result += ": " + formatted;
    }
    if (message != nullptr) {
      LocalFree(message);
    }
    return result;
  }

  inline const char* mode_name(RuntimeMode mode) {
    switch (mode) {
    case RuntimeMode::live:
      return "live";
    case RuntimeMode::headless:
      return "headless";
    case RuntimeMode::architecture_report:
      return "architecture-report";
    default:
      return "unknown";
    }
  }

  inline RuntimeMode parse_mode(const std::string& value) {
    if (value == "live") {
      return RuntimeMode::live;
    }
    if (value == "headless") {
      return RuntimeMode::headless;
    }
    if (value == "architecture-report" || value == "architecture") {
      return RuntimeMode::architecture_report;
    }
    throw std::runtime_error("[-] Unknown --mode value \"" + value + "\". Use live, headless, or architecture-report.");
  }

  inline uint32_t parse_u32(const std::string& value, const char* option, uint32_t minimum, uint32_t maximum) {
    errno = 0;
    char* end = nullptr;
    const auto parsed = std::strtoul(value.c_str(), &end, 10);
    if (
      errno != 0 ||
      end == value.c_str() ||
      *end != '\0' ||
      parsed < static_cast<unsigned long>(minimum) ||
      parsed > static_cast<unsigned long>(maximum)
    ) {
      throw std::runtime_error(
        "[-] Invalid " + std::string{ option } + " value \"" + value + "\"."
      );
    }
    return static_cast<uint32_t>(parsed);
  }

  inline std::string option_value(const std::string& argument, const char* option) {
    const auto prefix = std::string{ option } + "=";
    if (argument.rfind(prefix, 0) != 0) {
      return {};
    }
    return argument.substr(prefix.size());
  }

  inline std::string require_next_value(int& index, int argc, char* argv[], const char* option) {
    if (index + 1 >= argc) {
      throw std::runtime_error("[-] Missing value for " + std::string{ option } + ".");
    }
    ++index;
    return argv[index];
  }

  inline void print_usage(const char* executable, const RuntimeTraits& traits) {
    printf("Usage: %s [--architecture-report] [--mode live|headless] [--rounds N] [--period-ms N]\n", executable);
    printf("       %s --mode architecture-report\n", executable);
    printf("\n");
    printf("Gargoyle %s benign timer/APC runtime demo.\n", traits.display_name);
    printf("Default live period: %lu ms. Default headless period: %lu ms.\n",
      live_default_period_ms,
      headless_default_period_ms);
  }

  inline RuntimeOptions parse_options(int argc, char* argv[]) {
    auto options = RuntimeOptions{};

    for (int index = 1; index < argc; ++index) {
      const auto argument = std::string{ argv[index] };
      if (argument == "--help" || argument == "-h") {
        options.show_help = true;
        return options;
      }
      if (argument == "--architecture-report" || argument == "architecture-report") {
        options.mode = RuntimeMode::architecture_report;
        continue;
      }
      if (argument == "--headless") {
        options.mode = RuntimeMode::headless;
        continue;
      }
      if (argument == "--live") {
        options.mode = RuntimeMode::live;
        continue;
      }

      auto value = option_value(argument, "--mode");
      if (!value.empty() || argument == "--mode") {
        if (value.empty()) {
          value = require_next_value(index, argc, argv, "--mode");
        }
        options.mode = parse_mode(value);
        continue;
      }

      value = option_value(argument, "--rounds");
      if (!value.empty() || argument == "--rounds") {
        if (value.empty()) {
          value = require_next_value(index, argc, argv, "--rounds");
        }
        options.rounds = parse_u32(value, "--rounds", 1, 1000);
        continue;
      }

      value = option_value(argument, "--period-ms");
      if (!value.empty() || argument == "--period-ms") {
        if (value.empty()) {
          value = require_next_value(index, argc, argv, "--period-ms");
        }
        options.period_ms = parse_u32(value, "--period-ms", 1, 60 * 60 * 1000);
        options.period_was_set = true;
        continue;
      }

      throw std::runtime_error("[-] Unknown argument \"" + argument + "\". Use --help for usage.");
    }

    if (options.mode == RuntimeMode::headless && !options.period_was_set) {
      options.period_ms = headless_default_period_ms;
    }
    return options;
  }

  inline std::vector<uint8_t> read_binary(const std::string& filename) {
    std::fstream stream{ filename, std::fstream::in | std::fstream::ate | std::fstream::binary };
    if (!stream) {
      throw std::runtime_error("[-] Couldn't open \"" + filename + "\".");
    }

    const auto end = stream.tellg();
    if (end == std::fstream::pos_type(-1)) {
      throw std::runtime_error("[-] Empty or unreadable PIC file \"" + filename + "\".");
    }
    const auto size = static_cast<size_t>(end);
    if (size == 0) {
      throw std::runtime_error("[-] Empty PIC file \"" + filename + "\".");
    }
    stream.seekg(0, std::fstream::beg);

    auto result = std::vector<uint8_t>(size);
    stream.read(reinterpret_cast<char*>(result.data()), static_cast<std::streamsize>(result.size()));
    if (!stream) {
      throw std::runtime_error("[-] Couldn't read \"" + filename + "\".");
    }
    return result;
  }

  inline void* resolve_export(const wchar_t* module_name, const char* export_name) {
    auto module = GetModuleHandleW(module_name);
    if (module == nullptr) {
      module = LoadLibraryW(module_name);
    }
    if (module == nullptr) {
      throw std::runtime_error("[-] " + win32_error("LoadLibraryW"));
    }

    const auto address = GetProcAddress(module, export_name);
    if (address == nullptr) {
      throw std::runtime_error("[-] " + win32_error("GetProcAddress " + std::string{ export_name }));
    }
    return reinterpret_cast<void*>(address);
  }

  inline void* allocate_pic_region(size_t pic_size) {
#if defined(_M_ARM64EC)
    using VirtualAlloc2Fn = PVOID(WINAPI*)(
      HANDLE,
      PVOID,
      SIZE_T,
      ULONG,
      ULONG,
      MEM_EXTENDED_PARAMETER*,
      ULONG
    );

    const auto virtual_alloc2 =
      reinterpret_cast<VirtualAlloc2Fn>(resolve_export(L"kernelbase.dll", "VirtualAlloc2"));
    MEM_EXTENDED_PARAMETER ec_code_parameter{};
    ec_code_parameter.Type = MemExtendedParameterAttributeFlags;
    ec_code_parameter.ULong64 = MEM_EXTENDED_PARAMETER_EC_CODE;

    const auto reservation = virtual_alloc2(
      GetCurrentProcess(),
      nullptr,
      pic_size,
      MEM_RESERVE,
      PAGE_EXECUTE_READ,
      &ec_code_parameter,
      1
    );
    if (reservation == nullptr) {
      throw std::runtime_error("[-] " + win32_error("VirtualAlloc2 EC_CODE PIC reservation"));
    }

    const auto memory = VirtualAlloc(reservation, pic_size, MEM_COMMIT, PAGE_READWRITE);
    if (memory == nullptr) {
      const auto error = GetLastError();
      VirtualFree(reservation, 0, MEM_RELEASE);
      throw std::runtime_error("[-] " + win32_error("VirtualAlloc EC_CODE PIC commit", error));
    }
    return memory;
#else
    const auto memory = VirtualAlloc(nullptr, pic_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (memory == nullptr) {
      throw std::runtime_error("[-] " + win32_error("VirtualAlloc PIC allocation"));
    }
    return memory;
#endif
  }

  inline void* allocate_pic(const std::string& filename, size_t& pic_size) {
    const auto bytes = read_binary(filename);
    pic_size = bytes.size();

    const auto memory = allocate_pic_region(pic_size);
    std::memcpy(memory, bytes.data(), bytes.size());

    DWORD old_protection = 0;
    if (!VirtualProtect(memory, pic_size, PAGE_EXECUTE_READ, &old_protection)) {
      throw std::runtime_error("[-] " + win32_error("VirtualProtect PIC protection"));
    }
    if (!FlushInstructionCache(GetCurrentProcess(), memory, pic_size)) {
      throw std::runtime_error("[-] " + win32_error("FlushInstructionCache PIC bytes"));
    }
    return memory;
  }

#if defined(_M_ARM64EC)
  inline BOOL WINAPI arm64ec_virtual_protect_ex(
    HANDLE process,
    LPVOID address,
    SIZE_T size,
    DWORD new_protection,
    PDWORD old_protection
  ) {
    return VirtualProtectEx(process, address, size, new_protection, old_protection);
  }

  inline DWORD WINAPI arm64ec_sleep_ex(DWORD milliseconds, BOOL alertable) {
    return SleepEx(milliseconds, alertable);
  }

  inline HANDLE WINAPI arm64ec_create_waitable_timer_w(
    LPSECURITY_ATTRIBUTES timer_attributes,
    BOOL manual_reset,
    LPCWSTR timer_name
  ) {
    return CreateWaitableTimerW(timer_attributes, manual_reset, timer_name);
  }

  inline BOOL WINAPI arm64ec_set_waitable_timer(
    HANDLE timer,
    const LARGE_INTEGER* due_time,
    LONG period,
    PTIMERAPCROUTINE completion_routine,
    LPVOID completion_argument,
    BOOL resume
  ) {
    return SetWaitableTimer(timer, due_time, period, completion_routine, completion_argument, resume);
  }

  inline int WINAPI arm64ec_message_box_a(HWND window, LPCSTR text, LPCSTR caption, UINT type) {
    return MessageBoxA(window, text, caption, type);
  }
#endif

  inline const char* machine_name(USHORT machine) {
    switch (machine) {
    case IMAGE_FILE_MACHINE_UNKNOWN:
      return "unknown";
    case IMAGE_FILE_MACHINE_I386:
      return "x86";
    case IMAGE_FILE_MACHINE_AMD64:
      return "x64";
    case IMAGE_FILE_MACHINE_ARM64:
      return "ARM64";
    case IMAGE_FILE_MACHINE_ARM64EC:
      return "ARM64EC";
    default:
      return "unrecognized";
    }
  }

  inline const char* processor_architecture_name(WORD architecture) {
    switch (architecture) {
    case PROCESSOR_ARCHITECTURE_INTEL:
      return "x86";
    case PROCESSOR_ARCHITECTURE_AMD64:
      return "x64";
    case PROCESSOR_ARCHITECTURE_ARM:
      return "ARM";
    case PROCESSOR_ARCHITECTURE_ARM64:
      return "ARM64";
    default:
      return "unknown";
    }
  }

  inline void print_architecture_report(const RuntimeTraits& traits) {
    SYSTEM_INFO native_system_info{};
    GetNativeSystemInfo(&native_system_info);

    USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    const auto kernel32 = GetModuleHandleW(L"kernel32.dll");
    const auto is_wow64_process2 = kernel32 == nullptr
      ? nullptr
      : reinterpret_cast<IsWow64Process2Fn>(GetProcAddress(kernel32, "IsWow64Process2"));
    const auto has_machine_report = is_wow64_process2 != nullptr &&
      is_wow64_process2(GetCurrentProcess(), &process_machine, &native_machine);

    printf("[+] Gargoyle %s architecture report.\n", traits.display_name);
    printf("platform=%s\n", traits.file_suffix);
    printf("machine=%s\n", traits.display_name);
    printf("pointer_bits=%zu\n", sizeof(void*) * 8);
    printf("    Build target @ --------> %s\n", traits.display_name);
    printf("    Artifact suffix @ -----> %s\n", traits.file_suffix);
    printf("    Pointer size @ --------> %zu bytes\n", sizeof(void*));
    printf("    Native processor @ ----> %s (%hu)\n",
      processor_architecture_name(native_system_info.wProcessorArchitecture),
      native_system_info.wProcessorArchitecture);
    if (has_machine_report) {
      printf("    Process machine @ -----> 0x%04hx (%s)\n", process_machine, machine_name(process_machine));
      printf("    Native machine @ ------> 0x%04hx (%s)\n", native_machine, machine_name(native_machine));
    } else {
      printf("    Process machine @ -----> unavailable\n");
      printf("    Native machine @ ------> unavailable\n");
    }
  }

  inline void print_configuration_banner(
    const RuntimeTraits& traits,
    const RuntimeOptions& options,
    const ArmConfiguration& config,
    void* setup_memory,
    void* reentry_memory
  ) {
    printf("[+] %s timer/APC prototype configured.\n", traits.display_name);
    printf("    ================================\n");
    printf("    Gargoyle %s PIC @ ------> 0x%p\n", traits.display_name, setup_memory);
    printf("    %s re-entry PIC @ -----> 0x%p\n", traits.display_name, reentry_memory);
    printf("    %s APC callback @ ------> 0x%p\n", traits.display_name, config.reentry_callback);
    printf("    Configuration @ ----------> 0x%p\n", &config);
    printf("    VirtualProtectEx @ -------> 0x%p\n", config.VirtualProtectEx);
    printf("    SleepEx @ -------------> 0x%p\n", config.SleepEx);
    printf("    CreateWaitableTimerW @ ---> 0x%p\n", config.CreateWaitableTimerW);
    printf("    SetWaitableTimer @ -------> 0x%p\n", config.SetWaitableTimer);
    printf("    MessageBoxA @ ------------> 0x%p\n", config.MessageBoxA);
    printf("    Timer period @ -----------> %lu ms\n", options.period_ms);
    printf("    Runtime mode @ -----------> %s\n", mode_name(options.mode));
    printf("    Requested rounds @ -------> %lu\n", static_cast<unsigned long>(options.rounds));
  }

  inline void close_timer_handle(void* handle) {
    if (handle != nullptr) {
      CancelWaitableTimer(static_cast<HANDLE>(handle));
      CloseHandle(static_cast<HANDLE>(handle));
    }
  }

  inline void launch(const RuntimeTraits& traits, const RuntimeOptions& options) {
    printf("[ ] Loading %s setup PIC from \"%s\".\n", traits.display_name, traits.setup_pic);
    size_t setup_size = 0;
    const auto setup_memory = allocate_pic(traits.setup_pic, setup_size);
    printf("[+] Loaded %zu bytes of %s setup PIC.\n", setup_size, traits.display_name);

    printf("[ ] Loading %s re-entry PIC from \"%s\".\n", traits.display_name, traits.reentry_pic);
    size_t reentry_size = 0;
    const auto reentry_memory = allocate_pic(traits.reentry_pic, reentry_size);
    const auto reentry_callback =
      static_cast<void*>(static_cast<uint8_t*>(reentry_memory) + reentry_callback_offset);
    printf("[+] Loaded %zu bytes of %s re-entry PIC.\n", reentry_size, traits.display_name);

    auto config = ArmConfiguration{};
    config.setup_address = setup_memory;
    config.setup_length = setup_size;
    config.reentry_wait = reentry_memory;
    config.reentry_callback = reentry_callback;
#if defined(_M_ARM64EC)
    config.VirtualProtectEx = reinterpret_cast<void*>(&arm64ec_virtual_protect_ex);
    config.SleepEx = reinterpret_cast<void*>(&arm64ec_sleep_ex);
    config.CreateWaitableTimerW = reinterpret_cast<void*>(&arm64ec_create_waitable_timer_w);
    config.SetWaitableTimer = reinterpret_cast<void*>(&arm64ec_set_waitable_timer);
    config.MessageBoxA = reinterpret_cast<void*>(&arm64ec_message_box_a);
#else
    config.VirtualProtectEx = resolve_export(L"kernel32.dll", "VirtualProtectEx");
    config.SleepEx = resolve_export(L"kernel32.dll", "SleepEx");
    config.CreateWaitableTimerW = resolve_export(L"kernel32.dll", "CreateWaitableTimerW");
    config.SetWaitableTimer = resolve_export(L"kernel32.dll", "SetWaitableTimer");
    config.MessageBoxA = resolve_export(L"user32.dll", "MessageBoxA");
#endif
    config.due_time = -static_cast<int64_t>(options.period_ms) * 10000;
    config.interval = options.period_ms;
    config.mode = options.mode == RuntimeMode::live ? 0U : 1U;
    config.remaining_rounds = options.rounds;

    print_configuration_banner(traits, options, config, setup_memory, reentry_memory);
    printf("[ ] Entering benign %s PIC payload loop.\n", traits.display_name);

    reinterpret_cast<PicEntry>(setup_memory)(&config);
    close_timer_handle(config.sleep_handle);

    const auto expected_callbacks = options.rounds - 1;
    printf("[+] %s PIC completed %lu/%lu benign %s rounds with %lu timer/APC callbacks.\n",
      traits.display_name,
      static_cast<unsigned long>(config.completed_rounds),
      static_cast<unsigned long>(options.rounds),
      mode_name(options.mode),
      static_cast<unsigned long>(config.callback_rounds));

    if (config.completed_rounds != options.rounds) {
      throw std::runtime_error("[-] PIC returned before completing the requested rounds.");
    }
    if (config.callback_rounds < expected_callbacks) {
      throw std::runtime_error("[-] PIC returned before the requested timer/APC callbacks fired.");
    }
  }

  inline int run_arm_runtime(const RuntimeTraits& traits, int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    try {
      const auto options = parse_options(argc, argv);
      if (options.show_help) {
        print_usage(argv[0], traits);
        return 0;
      }
      if (options.mode == RuntimeMode::architecture_report) {
        print_architecture_report(traits);
        return 0;
      }
      launch(traits, options);
    } catch (const std::exception& e) {
      printf("%s\n", e.what());
      return 1;
    }
    return 0;
  }
}
