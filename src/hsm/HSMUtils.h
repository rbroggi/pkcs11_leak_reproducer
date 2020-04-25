//
// Created by rbroggi on 4/8/20.
//

#pragma once

#include "hsm/cryptoki.h"
#include <optional>
#include <tuple>
#include <vector>

/**
 * Utils used for interface with HSM
 * Favor using nox::fkk::hsm::HSMInterface for better resources allocation/cleaning
 */
class HSMUtils {
 public:
  /**
   * @param iLibPath - path to the DL lib to be opened
   * @return tuple where:
   *  1. is a pointer to void to the lib (output of dlopen method) - nullptr if error occurs
   *  2. is the function pointer containing the dl method list - nullptr if error occurs
   */
  static std::pair<void*, CK_FUNCTION_LIST_PTR> openHSMDL(const std::string& iLibPath);

  /**
   * @param iLib - the library being closed
   * @param iFunctionList - the function list on the library
   * @return
   *  false in case of error during dl close, true otherwise
   *
   */
  static bool closeHSMDL(void*& iLib, CK_FUNCTION_LIST_PTR iFunctionList);

  /**
   * @param iLibInterface - the function list of the dynamic lib
   * @param iSlotLabel - label of slot
   * @return
   *  empty optional if error occurs, a session otherwise (yet to be logged in)
   */
  static std::optional<CK_SESSION_HANDLE> openSession(CK_FUNCTION_LIST_PTR iLibInterface, const std::string& iSlotLabel);

  /**
   * @param iLibInterface - the function list of the dynamic lib
   * @param iSession - the session to be closed
   * @return
   *  false if an error occur, true otherwise
   */
  static bool closeSession(CK_FUNCTION_LIST_PTR iLibInterface, CK_SESSION_HANDLE& iSession);


  /**
   * @param iLibInterface - the function list of the dynamic lib
   * @param iSession - an HSM session
   * @param iSlotPwd - pwd for the slot of the underlying session
   * @return
   *  true if login successful
   *  false if login failed
   */
  static bool login(CK_FUNCTION_LIST_PTR iLibInterface, CK_SESSION_HANDLE iSession, const std::string& iSlotPwd);


  /**
   * @param iLibInterface - the function list of the dynamic lib
   * @param iSession - an HSM session
   * @param iKeyLabel - the key label to be found
   * @return
   *  empty optional if there is a search error or if no key is found
   */
  static std::optional<CK_OBJECT_HANDLE> retrieveKeyHandle(CK_FUNCTION_LIST_PTR iLibInterface, CK_SESSION_HANDLE iSession, const std::string& iKeyLabel);


  static std::optional<CK_OBJECT_HANDLE> generateKey(CK_FUNCTION_LIST_PTR iLibInterface, CK_SESSION_HANDLE iSession, const std::string& iKeyLabel);

  static std::optional<std::vector<unsigned char>> encrypt_aes(CK_FUNCTION_LIST_PTR iLibInterface, CK_SESSION_HANDLE iSession, CK_OBJECT_HANDLE iKeyHandle,  const std::vector<unsigned char>& iPlainText);

  static std::optional<std::vector<unsigned char>> decrypt_aes(CK_FUNCTION_LIST_PTR iLibInterface, CK_SESSION_HANDLE iSession, CK_OBJECT_HANDLE iKeyHandle,  const std::vector<unsigned char>& iCipherText);


};
