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

  struct X64Configuration {
    uint64_t initialized;
    void* setup_address;
    uint64_t setup_length;
    void* VirtualProtectEx;
    void* MessageBoxA;
    uint32_t old_protection;
    uint32_t reserved;
  };

  static_assert(sizeof(void*) == 8, "GargoyleX64 must be built as a 64-bit target.");
  static_assert(offsetof(X64Configuration, initialized) == 0x00);
  static_assert(offsetof(X64Configuration, setup_address) == 0x08);
  static_assert(offsetof(X64Configuration, setup_length) == 0x10);
  static_assert(offsetof(X64Configuration, VirtualProtectEx) == 0x18);
  static_assert(offsetof(X64Configuration, MessageBoxA) == 0x20);
  static_assert(offsetof(X64Configuration, old_protection) == 0x28);

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

  auto config = X64Configuration{};
  config.setup_address = setup_memory;
  config.setup_length = setup_size;
  config.VirtualProtectEx = resolve_export(L"kernel32.dll", "VirtualProtectEx");
  config.MessageBoxA = resolve_export(L"user32.dll", "MessageBoxA");

  printf("[+] x64 prototype configured.\n");
  printf("    ================================\n");
  printf("    Gargoyle x64 PIC @ -> 0x%p\n", setup_memory);
  printf("    Configuration @ ----> 0x%p\n", &config);
  printf("    VirtualProtectEx @ -> 0x%p\n", config.VirtualProtectEx);
  printf("    MessageBoxA @ -----> 0x%p\n", config.MessageBoxA);
  printf("[ ] Entering benign x64 PIC payload.\n");

  reinterpret_cast<PicEntry>(setup_memory)(&config);

  printf("[+] x64 prototype returned.\n");
}

int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    launch("setup_x64.pic");
  } catch (const exception& e) {
    printf("%s\n", e.what());
    return 1;
  }
  return 0;
}
