#include "FelicaProvider.h"
#include <windows.h>
#include <shlwapi.h>

long g_cRef = 0;
HINSTANCE g_hinst = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hinst = hModule;
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

STDAPI DllCanUnloadNow()
{
    return (g_cRef > 0) ? S_FALSE : S_OK;
}

STDAPI DllGetClassObject(REFIID rclsid, REFIID riid, void** ppv)
{
    if (rclsid != CLSID_FelicaCredentialProvider)
        return CLASS_E_CLASSNOTAVAILABLE;

    CClassFactory* pFactory = new CClassFactory();
    if (!pFactory)
        return E_OUTOFMEMORY;

    HRESULT hr = pFactory->QueryInterface(riid, ppv);
    pFactory->Release();
    return hr;
}

// CClassFactory implementation

IFACEMETHODIMP CClassFactory::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IUnknown || riid == IID_IClassFactory)
    {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) CClassFactory::AddRef()
{
    return InterlockedIncrement(&_cRef);
}

IFACEMETHODIMP_(ULONG) CClassFactory::Release()
{
    ULONG cRef = InterlockedDecrement(&_cRef);
    if (0 == cRef)
        delete this;
    return cRef;
}

IFACEMETHODIMP CClassFactory::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv)
{
    if (pUnkOuter != NULL)
        return CLASS_E_NOAGGREGATION;

    CFelicaProvider* pProvider = new CFelicaProvider();
    if (!pProvider)
        return E_OUTOFMEMORY;

    HRESULT hr = pProvider->QueryInterface(riid, ppv);
    pProvider->Release();
    return hr;
}

IFACEMETHODIMP CClassFactory::LockServer(BOOL bLock)
{
    if (bLock)
        InterlockedIncrement(&g_cRef);
    else
        InterlockedDecrement(&g_cRef);
    return S_OK;
}
