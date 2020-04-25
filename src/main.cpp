#include <hsm/HSMUtils.h>
#include <iostream>
#include <vector>
#include <algorithm>

using namespace std::string_literals;

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
  std::cout << "Login successful." << std::endl;

  static std::string aMasterKey = "MASTER_KEY"s;
  // Retrieve Key and if does not exist generate
  auto keyRetrieval = HSMUtils::retrieveKeyHandle(libFunc, aSession.value(), aMasterKey);
  if (not keyRetrieval) {
    std::cout << "Could not retrieve key Handle." <<std::endl;
    keyRetrieval = HSMUtils::generateKey(libFunc, aSession.value(), aMasterKey);
    if (not keyRetrieval) {
      std::cout << "Could not generate missing key." <<std::endl;
      return 3;
    }
    std::cout << "Generated Key with handle: " << aMasterKey << std::endl;
  } else {
    std::cout << "Retrieved existing key with label: " << aMasterKey << std::endl;
  }

  static std::vector<unsigned char> aPayload{
      0x12, 0x13, 0x21, 0x98, 0x87, 0xFA, 0xAE, 0xA3,
      0x12, 0x13, 0x21, 0x98, 0x87, 0xFA, 0xAE, 0xA3,
      0x12, 0x13, 0x21, 0x98, 0x87, 0xFA, 0xAE, 0xA3,
      0x12, 0x13, 0x21, 0x98, 0x87, 0xFA, 0xAE, 0xA3,
  };

  //encrypt
  auto aCipherText = HSMUtils::encrypt_aes(libFunc, aSession.value(), keyRetrieval.value(), aPayload);
  if (not aCipherText) {
    std::cout << "Error while encrypting." << std::endl;
    return 4;
  }
  auto aDecryptedCipher = HSMUtils::decrypt_aes(libFunc, aSession.value(), keyRetrieval.value(), aCipherText.value());

  if (aPayload != aDecryptedCipher.value()) {
    std::cout << "Payload differ from decrypted cipher" << std::endl;
    std::cout << "A payload: " << std::endl;
    std::for_each(aPayload.cbegin(), aPayload.cend(), [](const auto& aByte){ std::cout << std::hex << (uint32_t)aByte << " ";});
    std::cout << std::endl;
    std::cout << "A deciphered: " << std::endl;
    std::for_each(aDecryptedCipher.value().cbegin(), aDecryptedCipher.value().cend(), [](const auto& aByte){ std::cout << std::hex << (uint32_t)aByte << " ";});
    return 5;
  } else {
    std::cout << "Successful test" << std::endl;
  }


  return 0;
}
