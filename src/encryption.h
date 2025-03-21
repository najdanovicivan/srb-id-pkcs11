#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "pkcs11.h"

extern "C" {
CK_DECLARE_FUNCTION(CK_RV, C_EncryptInit)(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey);

CK_DECLARE_FUNCTION(CK_RV, C_Encrypt)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData,
	CK_ULONG ulDataLen,
	CK_BYTE_PTR pEncryptedData,
	CK_ULONG_PTR pulEncryptedDataLen);

CK_DECLARE_FUNCTION(CK_RV, C_EncryptUpdate)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG_PTR pulEncryptedPartLen);

CK_DECLARE_FUNCTION(CK_RV, C_EncryptFinal)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pLastEncryptedPart,
	CK_ULONG_PTR pulLastEncryptedPartLen);
}

#endif