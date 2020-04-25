#include <iostream>
#include "hsm/HSMUtils.h"

int main() {

  // opening dl
  auto libResult = HSMUtils::openHSMDL("/usr/local/lib/softhsm/libsofthsm2.so");
  if (libResult.first && libResult.second) {
    std::cout << "Lib was loaded!" << std::endl;
  } else {
    std::cout << "Lib not loaded!" << std::endl;
  }

  auto aSession = HSMUtils::openSession(libResult.second, "FKK");
  if (!aSession) {
    std::cout << "Could not open session." << std::endl;
  }

  return 0;
}
