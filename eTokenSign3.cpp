#include <windows.h>
#include <cryptuiapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <functional>

#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#pragma comment (lib, "cryptui.lib")
#pragma comment (lib, "crypt32.lib")

template<typename T>
class CustomAutoHandle
{
private:
	T	m_handle;
	std::function<void(T&)>	m_deleter;
public:
	operator bool(void) const
	{
		return (m_handle != NULL) && (m_handle != INVALID_HANDLE_VALUE);
	}
	operator T(void) const
	{
		return m_handle;
	}
public:
	CustomAutoHandle(T handle, std::function<void(T&)> f_deleter)
		: m_handle(handle), m_deleter(f_deleter)
	{
	}
	~CustomAutoHandle(void)
	{
		if (operator bool())
		{
			T	Handle = m_handle;
			m_handle = NULL;
			m_deleter(Handle);
		}//if
	}
};//template CustomAutoHandle

const std::wstring ETOKEN_BASE_CRYPT_PROV_NAME = L"eToken Base Cryptographic Provider";

std::string utf16_to_utf8(const std::wstring& str)
{
	if (str.empty())
	{
		return "";
	}

	auto utf8len = ::WideCharToMultiByte(CP_UTF8, 0, str.data(), str.size(), NULL, 0, NULL, NULL);
	if (utf8len == 0)
	{
		return "";
	}

	std::string utf8Str;
	utf8Str.resize(utf8len);
	::WideCharToMultiByte(CP_UTF8, 0, str.data(), str.size(), &utf8Str[0], utf8Str.size(), NULL, NULL);

	return utf8Str;
}
std::wstring utf8_to_utf16(const std::string& str)
{
	if (str.empty())
	{
		return L"";
	}

	auto widelen = ::MultiByteToWideChar(CP_UTF8, 0, str.data(), str.size(), NULL, 0);
	if (widelen == 0)
	{
		return L"";
	}

	std::wstring wideStr;
	wideStr.resize(widelen);
	::MultiByteToWideChar(CP_UTF8, 0, str.data(), str.size(), &wideStr[0], wideStr.size());

	return wideStr;
}

struct CryptProvHandle
{
    HCRYPTPROV Handle = NULL;
    CryptProvHandle(HCRYPTPROV handle = NULL) : Handle(handle) {}
    ~CryptProvHandle() { if (Handle) ::CryptReleaseContext(Handle, 0); }
};

#define MAX_BUFFER_LENGTH 256

void listCerts(CryptProvHandle cryptProv, CustomAutoHandle<HCERTSTORE> hSystemStore) {
	PCCERT_CONTEXT  pListCert = NULL;
	while ((pListCert = CertEnumCertificatesInStore(hSystemStore, pListCert)))
	{
		DWORD pdwKeySpec = 0;
		BOOL pfCallerFreeProvOrNCryptKey = false;
		CryptAcquireCertificatePrivateKey(pListCert, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL,
			&cryptProv.Handle, &pdwKeySpec, &pfCallerFreeProvOrNCryptKey);
		if (pdwKeySpec != AT_KEYEXCHANGE) {
			continue;
		}

		{
			wchar_t wbuf[MAX_BUFFER_LENGTH];
			if (CertGetNameStringW(pListCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, wbuf, MAX_BUFFER_LENGTH)) {
				std::wcerr << "    Name:      " << utf16_to_utf8(wbuf).c_str() << "\n";
			}
			if (CertGetNameStringW(pListCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, wbuf, MAX_BUFFER_LENGTH)) {
				std::wcerr << "    Issued by: " << utf16_to_utf8(wbuf).c_str() << "\n";
			}
		}


		{
			char cBuf[MAX_BUFFER_LENGTH];
			{
				SYSTEMTIME sysTime;
				FileTimeToSystemTime(&pListCert->pCertInfo->NotAfter, &sysTime);
				sprintf(cBuf, "%d-%02d-%02d %02d:%02d:%02d",
					sysTime.wYear, sysTime.wMonth, sysTime.wDay,
					sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
				std::wcerr << "    Expires:   " << cBuf << "\n";
			}
			{
				DWORD thumbPrintSize = 20;
				BYTE thumbPrint[20];
				if (CryptHashCertificate(NULL, 0, 0, pListCert->pbCertEncoded,
					pListCert->cbCertEncoded, thumbPrint, &thumbPrintSize)) {
					for (int i = 0; i < thumbPrintSize; ++i) {
						sprintf(cBuf + i * 2, "%02X", thumbPrint[i]);
					}
					cBuf[thumbPrintSize * 2] = 0;
					std::wcerr << "    SHA1 hash: " << cBuf << "\n";
				}
			}
		}

		std::wcerr << "\n";
	}
}

void help(void)
{
	std::wcerr << u8"usage: etokensign.exe <token-PIN> [<certificate-sha1> <timestamp-URL> <path-to-file-to-sign>]\n";
	std::wcerr << u8"(C) 2018 panagenda GmbH, (C) 2020 Fredrik Lidström";
}

int wmain(int argc, wchar_t** argv)
{
	SetConsoleOutputCP(CP_UTF8); 
	
	if (argc < 2) {
		help();
		return 1;
	}
	const std::wstring tokenPin = argv[1];
	const std::wstring tokenNumber = L"0";

	//-------------------------------------------------------------------
	// Unlock the token and get the provider handle
	CryptProvHandle cryptProv;
	std::wstring tokenName = L"\\\\.\\AKS ifdh " + tokenNumber;

	// CryptSetProvParam failed, error 0x8010006b  means the logon was unsuccessful
	if (!::CryptAcquireContext(&cryptProv.Handle, tokenName.c_str(), ETOKEN_BASE_CRYPT_PROV_NAME.c_str(), PROV_RSA_FULL, CRYPT_SILENT))
	{
		std::wcerr << "CryptAcquireContext failed, error " << std::hex << std::showbase << ::GetLastError() << "\n";
		return 1;
	}
	if (!::CryptSetProvParam(cryptProv.Handle, PP_SIGNATURE_PIN, reinterpret_cast<const BYTE*>(utf16_to_utf8(tokenPin).c_str()), 0))
	{
		std::wcerr << "CryptSetProvParam failed, error " << std::hex << std::showbase << ::GetLastError() << "\n";
		return 1;
	}
	if (cryptProv.Handle == NULL) {
		std::wcerr << "No provider handle returned\n";
		return 1;
	}

	//-------------------------------------------------------------------
	// Open the certificate store to be searched.
	CustomAutoHandle<HCERTSTORE> hSystemStore(
		CertOpenStore(
			CERT_STORE_PROV_SYSTEM,
			0,                      // Encoding type not needed with this PROV.
			NULL,                   // Accept the default HCRYPTPROV.
			CERT_SYSTEM_STORE_CURRENT_USER, // Set the system store location in the registry.
			L"MY"					// Could have used other predefined system stores including Trust, CA, or Root.
		),
		[](HCERTSTORE& h_cs) {CertCloseStore(h_cs, CERT_CLOSE_STORE_CHECK_FLAG); }
	);
	if (!hSystemStore)
	{
		std::wcerr << "Could not open the MY system store.\n";
		return 1;
	}

	if (argc < 3) {
		std::wcerr << "List of certificates:\n\n";
		// List all available certificates to make things easier

		listCerts(cryptProv, hSystemStore);
		return 1;
	}
	else if (argc < 5) {
		help();
		return 1;
	}

	const std::wstring certHash = argv[2];
	const std::wstring timestampUrl = argv[3];
	const std::wstring fileToSign = argv[4];

	//-------------------------------------------------------------------
	// Find the desired certificate
	PCCERT_CONTEXT  pDesiredCert = NULL;   // Set to NULL for the first call to CertFindCertificateInStore.

	bool bFound = false;
	DWORD cbSize = 0;
	while (!bFound && (pDesiredCert = CertEnumCertificatesInStore(hSystemStore, pDesiredCert)))
	{
		if (!(cbSize = CertGetNameString(pDesiredCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0)))
		{
			std::wcerr << L"Error on getting name size. Continue with next certificate.\n";
			continue;
		}
		std::vector<TCHAR> pszName(cbSize);
		if (!CertGetNameString(pDesiredCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, &pszName[0], cbSize))
		{
			std::wcerr << "Error on getting name. Continue with next certificate.\n";
			continue;
		}

		// Get the SHA1 for the certificate
		{
			DWORD thumbPrintSize = 20;
			BYTE thumbPrint[20];
			char thumbString[41];
			{
				if (CryptHashCertificate(NULL, 0, 0, pDesiredCert->pbCertEncoded,
					pDesiredCert->cbCertEncoded, thumbPrint, &thumbPrintSize)) {
					for (int i = 0; i < thumbPrintSize; ++i) {
						sprintf(thumbString + i * 2, "%02X", thumbPrint[i]);
					}
					thumbString[thumbPrintSize * 2] = 0;
					if (stricmp(thumbString, utf16_to_utf8(certHash).c_str()) == 0) {
						bFound = true;
						break;
					}
				}
			}
		}
	}
	if (!bFound)
	{
		std::wcerr << "No matching certificate to sign found. Try one of:\n\n";
		// List all available certificates to make things easier

		listCerts(cryptProv, hSystemStore);
		return 1;
	}


    CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO extInfo = {};
    extInfo.dwSize = sizeof(extInfo);
    extInfo.pszHashAlg = szOID_NIST_sha256; // Use SHA256 instead of default SHA1

    CRYPTUI_WIZ_DIGITAL_SIGN_INFO signInfo = {};
    signInfo.dwSize = sizeof(signInfo);
    signInfo.dwSubjectChoice = CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE;
    signInfo.pwszFileName = fileToSign.c_str();
	signInfo.dwSigningCertChoice = CRYPTUI_WIZ_DIGITAL_SIGN_CERT;
	signInfo.pSigningCertContext = pDesiredCert;
    signInfo.pwszTimestampURL = timestampUrl.c_str();
    signInfo.pSignExtInfo = &extInfo;

	int rv = 0;
    if (!::CryptUIWizDigitalSign(CRYPTUI_WIZ_NO_UI, NULL, NULL, &signInfo, NULL))
    {
        std::wcerr << u8"CryptUIWizDigitalSign failed, error " << std::hex << std::showbase << ::GetLastError() << "\n";
        rv = 1;
    }
	else
	{
		std::wcout << u8"Successfully signed " << fileToSign << "\n";
	}

	//-------------------------------------------------------------------
	// Clean up.
	if (pDesiredCert)
	{
		CertFreeCertificateContext(pDesiredCert);
	}

    return rv;
}
