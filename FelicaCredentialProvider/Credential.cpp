#include "FelicaProvider.h"
#include <Shlwapi.h>
#include <strsafe.h>
#include <wincred.h>
#include <ntsecapi.h>
#include "../lazypcscfelicalite.h"
#include "../felica_keys.h"

#pragma comment(lib, "Secur32.lib")

using namespace LazyPCSCFelicaLite;

namespace {
    void WriteToEventLog(WORD eventType, LPCWSTR message)
    {
        HANDLE hEventSource = RegisterEventSourceW(NULL, L"FelicaCredentialProvider");
        if (hEventSource != NULL)
        {
            LPCWSTR strings[1] = { message };
            ReportEventW(hEventSource, eventType, 0, 1000, NULL, 1, 0, strings, NULL);
            DeregisterEventSource(hEventSource);
        }
    }
}

// Same FID enum as Provider.cpp
enum FIELD_ID
{
    FID_LOGO = 0,
    FID_TITLE,
    FID_SUBMIT,
    NUM_FIELDS
};

CFelicaCredential::CFelicaCredential() : _cRef(1), _pEvents(NULL), _pProviderEvents(NULL), _upAdviseContext(0), _cardDetected(false), _stopPolling(false)
{
    InterlockedIncrement(&g_cRef);
}

CFelicaCredential::~CFelicaCredential()
{
    _stopPolling = true;
    if (_pollingThread.joinable())
    {
        _pollingThread.join();
    }
    if (_pEvents)
    {
        _pEvents->Release();
        _pEvents = NULL;
    }
    if (_pProviderEvents)
    {
        _pProviderEvents->Release();
        _pProviderEvents = NULL;
    }
    InterlockedDecrement(&g_cRef);
}

HRESULT CFelicaCredential::Initialize(ICredentialProviderEvents* pEvents, UINT_PTR upAdviseContext)
{
    // WriteToEventLog(EVENTLOG_INFORMATION_TYPE, L"CFelicaCredential::Initialize が呼び出されました。");
    _pProviderEvents = pEvents;
    if (_pProviderEvents)
        _pProviderEvents->AddRef();
    _upAdviseContext = upAdviseContext;
    return S_OK;
}

IFACEMETHODIMP CFelicaCredential::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential)
    {
        *ppv = static_cast<ICredentialProviderCredential*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) CFelicaCredential::AddRef()
{
    return InterlockedIncrement(&_cRef);
}

IFACEMETHODIMP_(ULONG) CFelicaCredential::Release()
{
    ULONG cRef = InterlockedDecrement(&_cRef);
    if (0 == cRef)
        delete this;
    return cRef;
}

IFACEMETHODIMP CFelicaCredential::Advise(ICredentialProviderCredentialEvents* pcpce)
{
    // WriteToEventLog(EVENTLOG_INFORMATION_TYPE, L"CFelicaCredential::Advise が呼び出されました。ポーリングスレッドを開始します。");
    _pEvents = pcpce;
    if (_pEvents)
    {
        _pEvents->AddRef();
        // Start polling thread
        _stopPolling = false;
        _pollingThread = std::thread(&CFelicaCredential::PollingThread, this);
    }
    return S_OK;
}

IFACEMETHODIMP CFelicaCredential::UnAdvise()
{
    _stopPolling = true;
    if (_pollingThread.joinable())
    {
        _pollingThread.join();
    }
    return S_OK;
}

IFACEMETHODIMP CFelicaCredential::SetSelected(BOOL* pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

IFACEMETHODIMP CFelicaCredential::SetDeselected()
{
    return S_OK;
}

IFACEMETHODIMP CFelicaCredential::SetDeserializedAuthenticationState(DWORD dwState)
{
    return S_OK;
}

IFACEMETHODIMP CFelicaCredential::GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    switch (dwFieldID)
    {
    case FID_LOGO:
        *pcpfs = CPFS_DISPLAY_IN_BOTH;
        *pcpfis = CPFIS_NONE;
        break;
    case FID_TITLE:
        *pcpfs = CPFS_DISPLAY_IN_BOTH;
        *pcpfis = CPFIS_NONE;
        break;
    case FID_SUBMIT:
        *pcpfs = CPFS_HIDDEN;
        *pcpfis = CPFIS_NONE;
        break;
    default:
        return E_INVALIDARG;
    }
    return S_OK;
}

IFACEMETHODIMP CFelicaCredential::GetStringValue(DWORD dwFieldID, LPWSTR* ppsz)
{
    if (dwFieldID == FID_TITLE)
    {
        return SHStrDupW(L"Touch FeliCa", ppsz);
    }
    return E_NOTIMPL;
}

IFACEMETHODIMP CFelicaCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CFelicaCredential::GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, LPWSTR* ppszLabel)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CFelicaCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    if (dwFieldID == FID_SUBMIT)
    {
        *pdwAdjacentTo = FID_TITLE;
        return S_OK;
    }
    return E_NOTIMPL;
}

IFACEMETHODIMP CFelicaCredential::GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcCount, DWORD* pdwComboBoxValue)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CFelicaCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, LPWSTR* ppszItem)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CFelicaCredential::SetStringValue(DWORD dwFieldID, LPCWSTR psz)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CFelicaCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CFelicaCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CFelicaCredential::CommandLinkClicked(DWORD dwFieldID)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CFelicaCredential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, LPWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    // WriteToEventLog(EVENTLOG_INFORMATION_TYPE, L"CFelicaCredential::GetSerialization が呼び出されました。資格情報をOSに提出します。");
    if (!_cardDetected)
    {
        return E_UNEXPECTED;
    }

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;

    // WriteToEventLog(EVENTLOG_INFORMATION_TYPE, L"GetSerialization: LsaRegisterLogonProcess を開始します。");
    ULONG ulAuthPackage;
    HANDLE hLsa;
    LSA_OPERATIONAL_MODE mode;
    LSA_STRING processName;
    processName.Buffer = (PCHAR)"FelicaLogon";
    processName.Length = (USHORT)strlen(processName.Buffer);
    processName.MaximumLength = processName.Length + 1;

    if (LsaRegisterLogonProcess(&processName, &hLsa, &mode) != 0)
    {
        // WriteToEventLog(EVENTLOG_INFORMATION_TYPE, L"GetSerialization: LsaRegisterLogonProcess 失敗。Untrustedでフォールバックします。");
        // フォールバック: Untrusted で接続
        if (LsaConnectUntrusted(&hLsa) != 0)
        {
            WriteToEventLog(EVENTLOG_ERROR_TYPE, L"GetSerialization: LsaConnectUntrusted も失敗しました。");
            return E_FAIL;
        }
    }

    LSA_STRING pkgName;
    pkgName.Buffer = (PCHAR)"Negotiate";
    pkgName.Length = (USHORT)strlen(pkgName.Buffer);
    pkgName.MaximumLength = pkgName.Length + 1;
    NTSTATUS status = LsaLookupAuthenticationPackage(hLsa, &pkgName, &ulAuthPackage);
    LsaDeregisterLogonProcess(hLsa);

    if (status != 0)
    {
        wchar_t msg[256];
        swprintf_s(msg, L"GetSerialization: LsaLookupAuthenticationPackage failed. Status: 0x%08X", status);
        WriteToEventLog(EVENTLOG_ERROR_TYPE, msg);
        return E_FAIL;
    }

    // WriteToEventLog(EVENTLOG_INFORMATION_TYPE, L"GetSerialization: パッケージ取得成功。シリアライズを開始します。");

    DWORD size = (DWORD)(sizeof(KERB_INTERACTIVE_LOGON) + 
                 (_username.length() + 1 + _domain.length() + 1 + _password.length() + 1) * sizeof(wchar_t));

    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(size);
    if (!pBuffer) return E_OUTOFMEMORY;

    ZeroMemory(pBuffer, size);
    KERB_INTERACTIVE_LOGON* pKerb = (KERB_INTERACTIVE_LOGON*)pBuffer;
    pKerb->MessageType = KerbInteractiveLogon;

    BYTE* pData = pBuffer + sizeof(KERB_INTERACTIVE_LOGON);

    pKerb->LogonDomainName.Length = (USHORT)(_domain.length() * sizeof(wchar_t));
    pKerb->LogonDomainName.MaximumLength = pKerb->LogonDomainName.Length + sizeof(wchar_t);
    pKerb->LogonDomainName.Buffer = (PWSTR)(pData - pBuffer);
    memcpy(pData, _domain.c_str(), pKerb->LogonDomainName.MaximumLength);
    pData += pKerb->LogonDomainName.MaximumLength;

    pKerb->UserName.Length = (USHORT)(_username.length() * sizeof(wchar_t));
    pKerb->UserName.MaximumLength = pKerb->UserName.Length + sizeof(wchar_t);
    pKerb->UserName.Buffer = (PWSTR)(pData - pBuffer);
    memcpy(pData, _username.c_str(), pKerb->UserName.MaximumLength);
    pData += pKerb->UserName.MaximumLength;

    pKerb->Password.Length = (USHORT)(_password.length() * sizeof(wchar_t));
    pKerb->Password.MaximumLength = pKerb->Password.Length + sizeof(wchar_t);
    pKerb->Password.Buffer = (PWSTR)(pData - pBuffer);
    memcpy(pData, _password.c_str(), pKerb->Password.MaximumLength);

    pcpcs->clsidCredentialProvider = CLSID_FelicaCredentialProvider;
    pcpcs->ulAuthenticationPackage = ulAuthPackage;
    pcpcs->cbSerialization = size;
    pcpcs->rgbSerialization = pBuffer;

    // WriteToEventLog(EVENTLOG_INFORMATION_TYPE, L"GetSerialization: シリアライズを完了し、LogonUIに返却します。");
    return S_OK;
}

IFACEMETHODIMP CFelicaCredential::ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus, LPWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    wchar_t msg[256];
    swprintf_s(msg, L"ReportResult: 認証が終了しました。Status: 0x%08X, Substatus: 0x%08X", ntsStatus, ntsSubstatus);
    
    if (ntsStatus == 0) {
        // WriteToEventLog(EVENTLOG_INFORMATION_TYPE, msg);
    } else {
        WriteToEventLog(EVENTLOG_WARNING_TYPE, msg);
    }

    _cardDetected = false;
    return S_OK;
}

void CFelicaCredential::PollingThread()
{
    PCSCFelicaLite felica(false);

    // 相互認証のための鍵 (felica_keys.h の定義を使用)
    uint8_t CK1[8] = FELICA_CK1_INIT;
    uint8_t CK2[8] = FELICA_CK2_INIT;

    while (!_stopPolling)
    {
        try
        {
            if (felica.autoConnectToFelica(500))
            {
                // WriteToEventLog(EVENTLOG_INFORMATION_TYPE, L"カードを検出しました。相互認証(MAC_A)を開始します。");
                // 相互認証 (外部認証によってカードを認証済み状態に遷移させる)
                felica.setSTATE_EXT_AUTH(true, CK1, CK2);
                
                {
                    uint8_t spad10[16] = {0};
                    uint8_t spad11[16] = {0};
                    uint8_t spad12[16] = {0};
                    uint8_t spad13[16] = {0};

                    uint8_t dummy_mac[16];
                    felica.readBinaryWithMAC_A(PCSCFelicaLite::ADDRESS_SPAD10, spad10, dummy_mac);
                    felica.readBinaryWithMAC_A(PCSCFelicaLite::ADDRESS_SPAD11, spad11, dummy_mac);
                    felica.readBinaryWithMAC_A(PCSCFelicaLite::ADDRESS_SPAD12, spad12, dummy_mac);
                    felica.readBinaryWithMAC_A(PCSCFelicaLite::ADDRESS_SPAD13, spad13, dummy_mac);

                    auto convertToWString = [](uint8_t* src, size_t maxLen) {
                        char ascii[33] = {0};
                        memcpy(ascii, src, maxLen);
                        int len = MultiByteToWideChar(CP_ACP, 0, ascii, -1, NULL, 0);
                        wchar_t* wideStr = new wchar_t[len];
                        MultiByteToWideChar(CP_ACP, 0, ascii, -1, wideStr, len);
                        std::wstring result = wideStr;
                        delete[] wideStr;
                        return result;
                    };

                    _username = convertToWString(spad10, 15); // max 15 chars for SPAD10
                    _password = convertToWString(spad11, 15); // max 15 chars for SPAD11
                    
                    uint8_t spad1213[32] = {0};
                    memcpy(spad1213, spad12, 16);
                    memcpy(spad1213 + 16, spad13, 15); // max 31 chars for SPAD12+13
                    _domain = convertToWString(spad1213, 31);
                    
                    if (_domain.empty())
                    {
                        _domain = L"."; // ローカルPCを指定
                    }

                    _cardDetected = true;
                    // WriteToEventLog(EVENTLOG_INFORMATION_TYPE, L"FeliCaカードの検出と相互認証に成功しました。ログイン処理に移行します。");

                    // Fire event to notify Logon UI to submit credential
                    if (_pProviderEvents)
                    {
                        _pProviderEvents->CredentialsChanged(_upAdviseContext);
                    }

                    // Wait until card is removed or stopped
                    while (!_stopPolling && felica.isCardSet(SCARD_STATE_UNAWARE, 500))
                    {
                        Sleep(500);
                    }
                }
            }
        }
        catch (const std::exception& e)
        {
            int len = MultiByteToWideChar(CP_ACP, 0, e.what(), -1, NULL, 0);
            wchar_t* wideStr = new wchar_t[len];
            MultiByteToWideChar(CP_ACP, 0, e.what(), -1, wideStr, len);
            std::wstring errMsg = L"例外発生: ";
            errMsg += wideStr;
            delete[] wideStr;
            WriteToEventLog(EVENTLOG_ERROR_TYPE, errMsg.c_str());
            Sleep(2000); // 連続ログを防ぐ
        }
        catch (...)
        {
            WriteToEventLog(EVENTLOG_ERROR_TYPE, L"不明な例外が発生しました。");
            Sleep(2000); // 連続ログを防ぐ
        }
        Sleep(500);
    }
}
