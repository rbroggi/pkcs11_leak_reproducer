#include <hsm/HSMUtils.h>
#include <iostream>

int main() {

  // opening dl
  auto [lib, libFunc] = HSMUtils::openHSMDL("/usr/local/lib/softhsm/libsofthsm2.so");
  if (lib && libFunc) {
    std::cout << "Lib was loaded!" << std::endl;
  } else {
    std::cout << "Lib not loaded!" << std::endl;
  }

  // opening session
  auto aSession = HSMUtils::openSession(libFunc, "FKH");
  if (not aSession) {
    std::cout << "Could not open session." << std::endl;
    return 1;
  }

  // login to session
  if (not HSMUtils::login(libFunc, aSession.value(), "1234")) {
    auto isSessionClosed = HSMUtils::closeSession(libFunc, aSession.value());
    auto isClosed        = HSMUtils::closeHSMDL(lib, libFunc);
    std::cout << "Could not login into session." << std::endl;
    return 2;
  }

  // create key inside

  std::cout << "Login successful." << std::endl;

  return 0;
}
