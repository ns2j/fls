#pragma once

#include <windows.h>
#include <credentialprovider.h>
#include <initguid.h>
#include <thread>
#include <atomic>
#include <string>

// TODO: Generate a unique GUID for your provider
DEFINE_GUID(CLSID_FelicaCredentialProvider, 0x904a0815, 0x4998, 0x4879, 0xa5, 0x8b, 0xa5, 0x9f, 0x6e, 0x24, 0x47, 0x01);

extern long g_cRef;

class CClassFactory : public IClassFactory
{
public:
    CClassFactory() : _cRef(1) {}
    
    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // IClassFactory
    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv);
    IFACEMETHODIMP LockServer(BOOL bLock);

private:
    ~CClassFactory() {}
    long _cRef;
};

class CFelicaCredential : public ICredentialProviderCredential
{
public:
    CFelicaCredential();
    HRESULT Initialize(ICredentialProviderEvents* pEvents, UINT_PTR upAdviseContext);

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP SetSelected(BOOL *pbAutoLogon);
    IFACEMETHODIMP SetDeselected();
    IFACEMETHODIMP SetDeserializedAuthenticationState(DWORD dwState);
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, LPWSTR* ppsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, LPWSTR* ppszLabel);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcCount, DWORD* pdwComboBoxValue);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, LPWSTR* ppszItem);
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, LPCWSTR psz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, LPWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus, LPWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    // Auto-logon のためにカード検出状態を取得するメソッド
    bool IsCardDetected() const { return _cardDetected; }

private:
    ~CFelicaCredential();
    void PollingThread();

    long _cRef;
    ICredentialProviderCredentialEvents* _pEvents;
    ICredentialProviderEvents* _pProviderEvents;
    UINT_PTR _upAdviseContext;
    std::thread _pollingThread;
    std::atomic<bool> _stopPolling;
    std::wstring _username;
    std::wstring _password;
    std::wstring _domain;
    bool _cardDetected;
};

class CFelicaProvider : public ICredentialProvider
{
public:
    CFelicaProvider();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc);

private:
    ~CFelicaProvider();

    long _cRef;
    ICredentialProviderEvents* _pEvents;
    UINT_PTR _upAdviseContext;
    CFelicaCredential* _pCredential;
};
