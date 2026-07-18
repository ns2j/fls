#include "FelicaProvider.h"
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

// The fields for our credential.
enum FIELD_ID
{
    FID_LOGO = 0,
    FID_TITLE,
    FID_SUBMIT,
    NUM_FIELDS
};

// Field descriptors
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgFieldDescriptors[] =
{
    { FID_LOGO, CPFT_TILE_IMAGE, (LPWSTR)L"Logo" },
    { FID_TITLE, CPFT_LARGE_TEXT, (LPWSTR)L"Title" },
    { FID_SUBMIT, CPFT_SUBMIT_BUTTON, (LPWSTR)L"Submit" }
};

CFelicaProvider::CFelicaProvider() : _cRef(1), _pEvents(NULL), _upAdviseContext(0), _pCredential(NULL)
{
    InterlockedIncrement(&g_cRef);
}

CFelicaProvider::~CFelicaProvider()
{
    if (_pEvents)
        _pEvents->Release();
    if (_pCredential)
        _pCredential->Release();
    InterlockedDecrement(&g_cRef);
}

IFACEMETHODIMP CFelicaProvider::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IUnknown || riid == IID_ICredentialProvider)
    {
        *ppv = static_cast<ICredentialProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) CFelicaProvider::AddRef()
{
    return InterlockedIncrement(&_cRef);
}

IFACEMETHODIMP_(ULONG) CFelicaProvider::Release()
{
    ULONG cRef = InterlockedDecrement(&_cRef);
    if (0 == cRef)
        delete this;
    return cRef;
}

IFACEMETHODIMP CFelicaProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags)
{
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        return S_OK;
    default:
        return E_NOTIMPL;
    }
}

IFACEMETHODIMP CFelicaProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CFelicaProvider::Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext)
{
    if (_pEvents)
        _pEvents->Release();
    _pEvents = pcpe;
    if (_pEvents)
        _pEvents->AddRef();
    _upAdviseContext = upAdviseContext;
    return S_OK;
}

IFACEMETHODIMP CFelicaProvider::UnAdvise()
{
    if (_pEvents)
    {
        _pEvents->Release();
        _pEvents = NULL;
    }
    _upAdviseContext = 0;
    return S_OK;
}

IFACEMETHODIMP CFelicaProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
    *pdwCount = NUM_FIELDS;
    return S_OK;
}

IFACEMETHODIMP CFelicaProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    if (dwIndex >= NUM_FIELDS)
        return E_INVALIDARG;

    *ppcpfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    if (!*ppcpfd)
        return E_OUTOFMEMORY;

    **ppcpfd = s_rgFieldDescriptors[dwIndex];
    if (s_rgFieldDescriptors[dwIndex].pszLabel)
    {
        SHStrDupW(s_rgFieldDescriptors[dwIndex].pszLabel, &(*ppcpfd)->pszLabel);
    }
    return S_OK;
}

IFACEMETHODIMP CFelicaProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault)
{
    *pdwCount = 1;
    *pdwDefault = 0;
    *pbAutoLogonWithDefault = FALSE;
    
    if (_pCredential && _pCredential->IsCardDetected())
    {
        *pbAutoLogonWithDefault = TRUE;
    }
    
    return S_OK;
}

IFACEMETHODIMP CFelicaProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc)
{
    if (dwIndex != 0)
        return E_INVALIDARG;

    if (!_pCredential)
    {
        _pCredential = new CFelicaCredential();
        if (!_pCredential)
            return E_OUTOFMEMORY;
        _pCredential->Initialize(_pEvents, _upAdviseContext);
    }

    *ppcpc = _pCredential;
    (*ppcpc)->AddRef();
    return S_OK;
}
