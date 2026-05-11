#include "../GargoyleArm64/arm_runtime.hpp"

#if !defined(_M_ARM64EC)
#error GargoyleArm64EC must be built as ARM64EC.
#endif

int main(int argc, char* argv[]) {
  constexpr gargoyle_arm::RuntimeTraits traits{
    "ARM64EC",
    "arm64ec",
    "setup_arm64ec.pic",
    "reentry_arm64ec.pic",
  };
  return gargoyle_arm::run_arm_runtime(traits, argc, argv);
}
