#include "arm_runtime.hpp"

#if defined(_M_ARM64EC)
#error GargoyleArm64 must be built as ARM64, not ARM64EC.
#endif

#if !defined(_M_ARM64)
#error GargoyleArm64 must be built as ARM64.
#endif

int main(int argc, char* argv[]) {
  constexpr gargoyle_arm::RuntimeTraits traits{
    "ARM64",
    "arm64",
    "setup_arm64.pic",
    "reentry_arm64.pic",
  };
  return gargoyle_arm::run_arm_runtime(traits, argc, argv);
}
