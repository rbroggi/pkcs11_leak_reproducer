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


using namespace std::string_literals;

// trim from start (in place)
static inline void ltrim(std::string &s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                                  std::not1(std::ptr_fun<int, int>(std::isspace))));
}

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
    remove_if(aSlotLabel.begin(), aSlotLabel.end(), isspace);
    /*
     * Open session on the slot
     */
    if (aSlotLabel == iSlotLabel) {

      const CK_FLAGS aSessionFlags = CKF_SERIAL_SESSION;
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

