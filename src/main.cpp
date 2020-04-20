#include <iostream>
#include "hsm/HSMUtils.h"

int main() {

  // opening dl
  auto libResult = HSMUtils::openHSMDL("/usr/local/lib/libpkcs11-proxy.so");
  if (libResult.first && libResult.second) {
    std::cout << "Lib was loaded!" << std::endl;
  } else {
    std::cout << "Lib not loaded!" << std::endl;
  }
  return 0;
}
