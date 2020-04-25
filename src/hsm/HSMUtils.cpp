//
// Created by rbroggi on 4/8/20.
//

#include "hsm/HSMUtils.h"
#include <algorithm>
#include <dlfcn.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>
#include <random>


using namespace std::string_literals;

constexpr const std::size_t K_IV_SIZE = 16u;
constexpr const std::size_t K_TAG_SIZE = 16u;
// authentication array
std::vector<unsigned char> gcmAAD = { 0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED,
                                      0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF, 0xAB, 0xAD, 0xDA, 0xD2 };

void TRC_ERROR(int error, const std::string& err) {
  std::cout << error << err;
}

void TRC_WARN(int error, const std::string& err) {
  std::cout << error << err;
}

std::pair<void*, CK_FUNCTION_LIST_PTR> HSMUtils::openHSMDL(const std::string& iLibPath) {

  void* aLib = dlopen(iLibPath.c_str(), RTLD_LAZY);
  if (not aLib) {
    std::ostringstream descr;
    descr << "HSM lib: " << iLibPath << " could not be opened, with error: " << std::string(dlerror());
    TRC_ERROR(255,  descr.str());
    return { nullptr, nullptr };
  }
  CK_C_GetFunctionList aGetFuncList = nullptr;
  static auto aGetFunctionListName  = "C_GetFunctionList";
  aGetFuncList                      = (CK_C_GetFunctionList)dlsym(aLib, aGetFunctionListName);
  if (not aGetFuncList) {
    dlclose(aLib);
    std::ostringstream descr;
    descr << "Could not load symbol C_GetFunctionList:  " << std::string(dlerror());
    TRC_ERROR(255,  descr.str());
    return { nullptr, nullptr };
  }

  CK_FUNCTION_LIST_PTR aFunctionList;
  aGetFuncList(&aFunctionList);
  if (not aFunctionList) {
    dlclose(aLib);
    TRC_ERROR(255,  "Could not get function list"s);
    return { nullptr, nullptr };
  }

  CK_RV result = aFunctionList->C_Initialize(nullptr);
  if (result == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    TRC_WARN(255,  "HSM lib already initialized"s);
  }
  else if (result != CKR_OK) {
    dlclose(aLib);
    std::ostringstream desc;
    desc << "Could not initialize HSM library " << std::hex << std::setw(2 * sizeof(CK_RV)) << std::setfill('0')
         << result;
    TRC_ERROR(255,  desc.str());
    return { nullptr, nullptr };
  }

  return { aLib, aFunctionList };
  }

bool HSMUtils::closeHSMDL(void*& iLib, CK_FUNCTION_LIST_PTR iFunctionList) {
  if ((iLib == nullptr) or (iFunctionList == nullptr)) {
    TRC_WARN(255,  "HSM lib already finalized.");
    return true;
  }

  CK_RV result = iFunctionList->C_Finalize(nullptr);
  if (result == CKR_CRYPTOKI_NOT_INITIALIZED) {
    TRC_WARN(255,  "HSM lib already finalized.");
  }
  else if (result != CKR_OK) {
    TRC_ERROR(255,  "HSM lib already finalized.");
    return false;
  }
  dlclose(iLib);
  iLib = nullptr;
  return true;
}
std::optional<CK_OBJECT_HANDLE> HSMUtils::retrieveKeyHandle(CK_FUNCTION_LIST_PTR iLibInterface,
                                                            CK_SESSION_HANDLE iSession,
                                                            const std::string& iKeyLabel) {

  CK_ATTRIBUTE aKeyTemplate[] = { { CKA_LABEL, const_cast<char*>(iKeyLabel.c_str()), iKeyLabel.length() } };

  // Initialize the search
  CK_RV aStatus = iLibInterface->C_FindObjectsInit(iSession, aKeyTemplate, 1);
  if (aStatus != CKR_OK) {
    std::stringstream aErrorMsg;
    aErrorMsg << "Error: C_FindObjectsInit returned 0x" << std::hex << aStatus;
    return {};
  }

  CK_ULONG aCount = 0u;
  CK_OBJECT_HANDLE aHandle;
  CK_RV aCKFindStatus = iLibInterface->C_FindObjects(iSession, &aHandle, 1, &aCount);
  if (aCKFindStatus != CKR_OK) {
    std::stringstream aErrorMsg;
    aErrorMsg << "Unable to find the Key: " << iKeyLabel << " - C_FindObjects returned 0x" << std::hex << aCKFindStatus;
    TRC_ERROR(255,  aErrorMsg.str());
  }
  else {
    if (aCount == 0u) {
      std::stringstream aErrorMsg;
      aErrorMsg << "Unable to find the Key: " << iKeyLabel << " - C_FindObjects found no key";
      TRC_ERROR(255,  aErrorMsg.str());
    }
  }

  // Close search
  CK_RV aCKCloseStatus = iLibInterface->C_FindObjectsFinal(iSession);
  if (aCKCloseStatus != CKR_OK) {
    std::stringstream aErrorMsg;
    aErrorMsg << "Error in C_FindObjectsFinal" << std::hex << aCKCloseStatus;
    TRC_ERROR(255,  aErrorMsg.str());
  }

  if ((aCKFindStatus != CKR_OK) || (aCKCloseStatus != CKR_OK) || (aCount == 0u)) {
    return {};
  }

  return { aHandle };
}

bool HSMUtils::login(CK_FUNCTION_LIST_PTR iLibInterface,
CK_SESSION_HANDLE iSession,
const std::string& iSlotPwd) {
/*
 * Log in
 */
const CK_USER_TYPE aUserType = CKU_USER;
CK_RV aStatus = iLibInterface->C_Login(iSession, aUserType, (CK_CHAR_PTR)iSlotPwd.c_str(), iSlotPwd.size());
if (aStatus != CKR_OK) {
    std::stringstream aErrorMsg;
    aErrorMsg << "Login to HSM failed - C_Login returned 0x" << std::hex << aStatus;
    TRC_ERROR(255,  aErrorMsg.str());
    return false;
  }
  return true;
}

std::optional<CK_SESSION_HANDLE> HSMUtils::openSession(CK_FUNCTION_LIST_PTR iLibInterface,
                                                       const std::string& iSlotLabel) {

  if (iLibInterface == nullptr) {
    TRC_ERROR(255,  "Empty lib interface functions.");
    return {};
  }

  CK_ULONG aSlotCount = 0u;
  CK_RV aStatus       = iLibInterface->C_GetSlotList((CK_BBOOL)TRUE, nullptr, &aSlotCount);
  if (aStatus != CKR_OK) {
    std::ostringstream descr;
    descr << "Error in C_GetSlotList: " << std::hex << aStatus;
    TRC_ERROR(255,  descr.str());
    return {};
  }
  if (aSlotCount == 0u) {
    std::ostringstream descr;
    descr << "C_GetSlotList retrieved 0 slots ";
    TRC_ERROR(255,  descr.str());
    return {};
  }

  std::vector<CK_SLOT_ID> aSlotList(aSlotCount, 0);
  aStatus = iLibInterface->C_GetSlotList((CK_BBOOL)TRUE, &aSlotList[0], &aSlotCount);
  if (aStatus != CKR_OK) {
    std::ostringstream descr;
    descr << "Error while retrieving slot list in C_GetSlotList: " << std::hex << aStatus;
    TRC_ERROR(255,  descr.str());
    return {};
  }

  for (CK_ULONG i = 0; i < aSlotCount; ++i) {

    CK_SLOT_ID aSlotId = aSlotList[i];
    CK_TOKEN_INFO aTokenInfo;
    aStatus = iLibInterface->C_GetTokenInfo(aSlotId, &aTokenInfo);
    if (aStatus != CKR_OK) {
      std::ostringstream aErrorMsg;
      aErrorMsg << "Unable to read HSM token in slot " << aSlotId << " while looking for slot " << iSlotLabel
                << " - C_GetTokenInfo returned 0x" << std::hex << aStatus;
      TRC_ERROR(255,  aErrorMsg.str());
      return {};
    }

    std::string aSlotLabel = std::string(reinterpret_cast<char*>(aTokenInfo.label), sizeof(aTokenInfo.label));
    aSlotLabel.erase(std::remove_if(aSlotLabel.begin(),
                                    aSlotLabel.end(),
                                    [](unsigned char x) { return std::isspace(x); }),
                     aSlotLabel.end());
    /*
     * Open session on the slot
     */
    if (aSlotLabel == iSlotLabel) {

      const CK_FLAGS aSessionFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
      CK_SESSION_HANDLE aSession;
      aStatus = iLibInterface->C_OpenSession(aSlotId, aSessionFlags, 0, 0, &aSession);
      if (aStatus != CKR_OK) {
        std::ostringstream aErrorMsg;
        aErrorMsg << "Unable to open HSM session " << iSlotLabel << " - C_OpenSession returned 0x" << std::hex
                  << aStatus;
        TRC_ERROR(255,  aErrorMsg.str());
        return {};
      }
      // return found session
      return { aSession };
    }
  }

  std::ostringstream descr;
  descr << "No slot id found for label: " << iSlotLabel;
  TRC_ERROR(255,  descr.str());
  return {};
}

bool HSMUtils::closeSession(CK_FUNCTION_LIST_PTR iLibInterface, CK_SESSION_HANDLE& iSession) {
  if (iLibInterface == nullptr) {
    TRC_ERROR(255,  "Empty lib interface functions.");
    return false;
  }

  if (iSession) {
    auto aStatus = iLibInterface -> C_Logout(iSession);
    if (aStatus != CKR_OK) {
      std::ostringstream aErrorMsg;
      aErrorMsg << "Error while calling C_Logout: 0x" << std::hex << aStatus;
      TRC_WARN(255,  aErrorMsg.str());
    }

    aStatus = iLibInterface -> C_CloseSession(iSession);
    if (aStatus != CKR_OK) {
      std::ostringstream aErrorMsg;
      aErrorMsg << "Error while calling C_CloseSession: 0x" << std::hex << aStatus;
      TRC_ERROR(255,  aErrorMsg.str());
      return false;
    }
  }

  return true;
}

std::optional<CK_OBJECT_HANDLE> HSMUtils::generateKey(CK_FUNCTION_LIST_PTR iLibInterface, CK_SESSION_HANDLE iSession, const std::string& iKeyLabel) {
  CK_MECHANISM mechanism = {
      CKM_AES_KEY_GEN, nullptr, 0};

  std::vector<CK_BYTE> keyLabel(iKeyLabel.begin(), iKeyLabel.end());

  static CK_OBJECT_CLASS KeyClass = CKO_SECRET_KEY;
  static CK_KEY_TYPE KeyType = CKK_AES;
  static CK_ULONG KeyLen = 32;
  static CK_BBOOL bTrue = true;
  static CK_BBOOL bFalse = true;

  std::vector<CK_ATTRIBUTE> attrs = {
      {CKA_CLASS, &KeyClass, sizeof(KeyClass)},
      {CKA_TOKEN, &bTrue, sizeof(bTrue)},
      {CKA_PRIVATE, &bTrue, sizeof(bTrue)},
      {CKA_LABEL, keyLabel.data(), keyLabel.size()},
      {CKA_ID, keyLabel.data(), keyLabel.size()},
      {CKA_MODIFIABLE, &bFalse, sizeof(bFalse)},
      {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
      {CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
      {CKA_DECRYPT, &bTrue, sizeof(bTrue)},
      {CKA_VALUE_LEN, &KeyLen, sizeof(KeyLen)}
  };

  CK_OBJECT_HANDLE aKey;
  CK_RV aStatus = iLibInterface->C_GenerateKey(iSession, &mechanism, attrs.data(), attrs.size(), &aKey);
  if (aStatus != CKR_OK) {
    std::ostringstream aErrorMsg;
    aErrorMsg << "Error while calling C_GenerateKey: 0x" << std::hex << aStatus;
    TRC_ERROR(255,  aErrorMsg.str());
    return {};
  }
  return {aKey};
}

std::optional<std::vector<unsigned char>> HSMUtils::encrypt_aes(CK_FUNCTION_LIST_PTR iLibInterface, CK_SESSION_HANDLE iSession, CK_OBJECT_HANDLE iKeyHandle, const std::vector<unsigned char> &iPlainText) {

  if (not iLibInterface) {
    TRC_ERROR(255, "Cannot encrypt due to empty lib iLibInterface interface");
    return {};
  }

  // Set up GCM params: IV, AAD,

  // Creating a random IV
  std::vector<unsigned char> gcmIV(K_IV_SIZE, 0x00);
  std::random_device rd;
  std::uniform_int_distribution<unsigned char> dist(0x00,0xFF);
  std::for_each(gcmIV.begin(), gcmIV.end(), [& dist = dist, &gen = rd](auto& el) { el = dist(gen); });

  CK_AES_GCM_PARAMS gcmParams = {
      &gcmIV.front(), gcmIV.size(), gcmIV.size() * 8u, &gcmAAD.front(), gcmAAD.size(), K_TAG_SIZE * 8u
  };

  CK_MECHANISM aMech = { CKM_AES_GCM, &gcmParams, sizeof(CK_AES_GCM_PARAMS) };

  CK_RV rv = iLibInterface->C_EncryptInit(iSession, &aMech, iKeyHandle);
  if (rv != CKR_OK) {
    std::stringstream descr;
    descr << "Failed in C_EncryptInit, return value: " << std::hex << rv;
    TRC_ERROR(255, descr.str());
    return {};
  }

  // Determine how much memory is required to store the ciphertext.
  CK_ULONG aCipherTextLength = 0;
  rv =
      iLibInterface->C_Encrypt(iSession, (CK_BYTE_PTR)&iPlainText.front(), iPlainText.size(), nullptr, &aCipherTextLength);
  if (rv != CKR_OK) {
    std::stringstream descr;
    descr << "Failed in C_Encrypt size, return value: " << std::hex << rv;
    TRC_ERROR(255, descr.str());
    return {};
  }

  // size ciphertext to contain enough space to prepended IV + cipheredtext
  std::vector<unsigned char> aCipherText(gcmIV);
  aCipherText.resize(gcmIV.size() + aCipherTextLength);
  // Start to write ciphertext to iv lenght in order to have IV prepended
  rv = iLibInterface->C_Encrypt(iSession,
                             (CK_BYTE_PTR)&iPlainText.front(),
                             iPlainText.size(),
                             &aCipherText[gcmIV.size()],
                             &aCipherTextLength);
  if (rv != CKR_OK) {
    std::ostringstream descr;
    descr << "Failed in C_Encrypt, return value: " << std::hex << rv;
    TRC_ERROR(255, descr.str());
    return {};
  }
  // Guaranteeing that the cipherlenght is still what promised before
  aCipherText.resize(gcmIV.size() + aCipherTextLength);

  return {  aCipherText };
}
std::optional<std::vector<unsigned char>> HSMUtils::decrypt_aes(CK_FUNCTION_LIST_PTR iLibInterface, CK_SESSION_HANDLE iSession, CK_OBJECT_HANDLE iKeyHandle, const std::vector<unsigned char> &iCipherText) {

  if (iLibInterface == nullptr) {
    TRC_ERROR(255, "Cannot decrypt due to empty lib iLibInterface interface");
    return {};
  }

  // cipher text should be at least as big as IV size plus gcmAAD size
  if (iCipherText.size() < (K_IV_SIZE + K_TAG_SIZE)) {
    std::ostringstream descr;
    descr << "Cipher text should be at least as big as IV size plus TAG size."
          << " IV size: " << K_IV_SIZE
          << "; TAG size: " << K_TAG_SIZE;
    TRC_ERROR(255, descr.str());
    return {};
  }

  // Set up GCM params: IV, AAD,

  // Retrieving IV from the iCipherText
  std::vector<unsigned char> gcmIV(iCipherText.begin(), iCipherText.begin() + K_IV_SIZE);

  CK_AES_GCM_PARAMS gcmParams = {
      &gcmIV.front(), gcmIV.size(), gcmIV.size() * 8u, &gcmAAD.front(), gcmAAD.size(), K_TAG_SIZE * 8u
  };

  CK_MECHANISM aMech = { CKM_AES_GCM, &gcmParams, sizeof(CK_AES_GCM_PARAMS) };

  CK_RV rv = iLibInterface->C_DecryptInit(iSession, &aMech, iKeyHandle);
  if (rv != CKR_OK) {
    std::stringstream descr;
    descr << "Failed in C_DecryptInit, return value: " << std::hex << rv;
    TRC_ERROR(255, descr.str());
    return {};
  }

  // Determine how much memory is required to store the plaintext.
  CK_ULONG aPlainTextLength = 0;
  rv = iLibInterface->C_Decrypt(iSession, (CK_BYTE_PTR)&iCipherText[K_IV_SIZE], iCipherText.size() - K_IV_SIZE, nullptr, &aPlainTextLength);
  if (rv != CKR_OK) {
    std::stringstream descr;
    descr << "Failed in C_Decrypt size, return value: " << std::hex << rv;
    TRC_ERROR(255, descr.str());
    return {};
  }

  // reserve size on plaintext to contain enough space to prepended IV + cipheredtext
  std::vector<unsigned char> aPlainText;
  aPlainText.resize(aPlainTextLength);
  // Start to write ciphertext to iv lenght in order to have IV prepended
  rv = iLibInterface->C_Decrypt(iSession,
                             (CK_BYTE_PTR)&iCipherText[K_IV_SIZE],
                             iCipherText.size() - K_IV_SIZE,
                             &aPlainText.front(),
                             &aPlainTextLength);
  if (rv != CKR_OK) {
    std::ostringstream descr;
    descr << "Failed in C_Decrypt, return value: " << std::hex << rv;
    TRC_ERROR(255, descr.str());
    return {};
  }

  // Guaranteeing that the cipherlenght is still what promised before
  aPlainText.resize(aPlainTextLength);

  return { aPlainText };
}
