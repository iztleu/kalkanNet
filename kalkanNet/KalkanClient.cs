namespace kalkanNet;

using System.Runtime.InteropServices;
using System.Text;

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate ulong KC_Init();    
    
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate ulong KC_GetLastError();  
    
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate ulong KC_GetLastErrorString(StringBuilder errorString, out int bufSize);    
    
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate ulong KC_LoadKeyStore(int storage, string password, int passLen, string container, int containerLen, string alias);    
    
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate ulong SignXML(string alias, int flags, string inData, int inDataLength, StringBuilder outSign, out int outSignoutSignLength, string signNodeId, string parentSignNode, string parentNameSpace);
    
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate int KC_GetFunctionList1(ref FunctionsType kc);

[StructLayout(LayoutKind.Sequential)]
public struct StKCFunctionsType
{
    public KC_Init KC_Init;
    public IntPtr KC_GetTokens;
    public IntPtr KC_GetCertificatesList;
    public KC_LoadKeyStore KC_LoadKeyStore;
    public IntPtr X509LoadCertificateFromFile;
    public IntPtr X509LoadCertificateFromBuffer;
    public IntPtr X509ExportCertificateFromStore;
    public IntPtr X509CertificateGetInfo;
    public IntPtr X509ValidateCertificate;
    public IntPtr HashData;
    public IntPtr SignHash;
    public IntPtr SignData;
    public SignXML SignXML;
    public IntPtr VerifyData;
    public IntPtr VerifyXML;
    public IntPtr KC_getCertFromXML;
    public IntPtr KC_getSigAlgFromXML;
    public KC_GetLastError KC_GetLastError;
    public KC_GetLastErrorString KC_GetLastErrorString;
    public IntPtr KC_XMLFinalize;
    public IntPtr KC_Finalize;
    public IntPtr KC_TSASetUrl;
    public IntPtr KC_GetTimeFromSig;
    public IntPtr KC_SetProxy;
    public IntPtr KC_GetCertFromCMS;
    public IntPtr SignWSSE;
    public IntPtr ZipConVerify;
    public IntPtr ZipConSign;
}

public class KalkanClient
{
    [DllImport("kalkancryptwr-64", CallingConvention = CallingConvention.Cdecl)]
    static extern int KC_GetFunctionList(out FunctionsType kc);

    private static StKCFunctionsType StKCFunctionsType;
    private static bool KcInit;

    static KalkanClient()
    {
        StKCFunctionsType kc = new StKCFunctionsType();

        int result = KC_GetFunctionList(out var functionsType);
        if (result != 0)
        {
            throw new InvalidOperationException($"Couldn't get function list result: {result}");
        }

        if (functionsType.stKCFunctionsType != IntPtr.Zero)
        {
            StKCFunctionsType = (StKCFunctionsType)Marshal.PtrToStructure(functionsType.stKCFunctionsType, typeof(StKCFunctionsType));
        }

        var errCode = StKCFunctionsType.KC_Init();
        ThrowIfError(errCode);
        KcInit = true;
    }

    public KalkanClient(KalkanOptions option, HttpClient httpClient)
    {
        HTTPClient = httpClient;
        Option = option;
    }

    public KalkanClient(KalkanOptions option)
        : this(option, new HttpClient())
    {
    }

    HttpClient HTTPClient { get; set; }
    KalkanOptions Option { get; set; }
    private bool KeyStoreLoaded { get; set; }

    public void LoadKeyStore(string password, string containerPath, KCStoreType storeType, string alias)
    {
        EnsureInitialized();
        var errCode = StKCFunctionsType.KC_LoadKeyStore((int)storeType, password, password.Length, containerPath, containerPath.Length, alias);
        ThrowIfError(errCode);

        KeyStoreLoaded = true;
    }
    
    public string SignXML(string xml, string alias, string signNodeId, string parentSignNode, string parentNameSpace)
    {
        EnsureInitialized();
        if (!KeyStoreLoaded)
        {
            throw new InvalidOperationException("Key store is not loaded");
        }

        var outSign = new StringBuilder(xml.Length + 5000); 
        var errCode = StKCFunctionsType.SignXML(alias, 0, xml, xml.Length, outSign, out var outSignLength, signNodeId, parentSignNode, parentNameSpace);
        ThrowIfError(errCode);
        return outSign.ToString();
    }
    
    public static List<OptionCert> GetProdCert()
    {
        return new List<OptionCert>
        {
            new(URL: "https://pki.gov.kz/cert/root_gost.crt", Type: KCCertType.KCCertTypeCA),
            new(URL: "https://pki.gov.kz/cert/root_rsa.crt", Type: KCCertType.KCCertTypeCA),
            new(URL: "https://pki.gov.kz/cert/root_gost2015_2022.cer", Type: KCCertType.KCCertTypeCA),
            new(URL: "https://pki.gov.kz/cert/nca_gost.crt", Type: KCCertType.KCCertTypeIntermediate),
            new(URL: "https://pki.gov.kz/cert/nca_rsa.crt", Type: KCCertType.KCCertTypeIntermediate),
            new(URL: "https://pki.gov.kz/cert/nca_gost2015.cer", Type: KCCertType.KCCertTypeIntermediate)
        };
    }

    public static List<OptionCert> GetTestCert()
    {
        return new List<OptionCert>
        {
            new(URL: "http://test.pki.gov.kz/cert/root_gost_test.cer", Type: KCCertType.KCCertTypeCA),
            new(URL: "http://test.pki.gov.kz/cert/root_rsa_test.cer", Type: KCCertType.KCCertTypeCA),
            new(URL: "http://test.pki.gov.kz/cert/nca_gost_test.cer", Type: KCCertType.KCCertTypeIntermediate),
            new(URL: "http://test.pki.gov.kz/cert/nca_rsa_test.cer", Type: KCCertType.KCCertTypeIntermediate)
        };
    }

    private static void EnsureInitialized()
    {
        if (!KcInit)
        {
            throw new InvalidOperationException("The Kalcancrypt was not initialized");
        }
    }

    private static void ThrowIfError(ulong errorCode)
    {
        if (errorCode == 0)
        {
            return;
        }

        var err = new StringBuilder(500);
        StKCFunctionsType.KC_GetLastErrorString(err, out _);
        throw new InvalidOperationException(err.ToString());
    }
}

public class KalkanOptions
{
    public string TCP { get; set; } = "http://tsp.pki.gov.kz:80";
    public string OCSP { get; set; } = "http://ocsp.pki.gov.kz";
    public Uri Proxy { get; set; }
    public List<OptionCert> Certs { get; set; }
    public string CRLGOST { get; set; } = "https://crl.pki.gov.kz/nca_gost.crl";
    public string CRLRSA { get; set; } = "https://crl.pki.gov.kz/nca_rsa.crl";
    public string CRLDeltaGOST { get; set; } = "https://crl.pki.gov.kz/nca_d_gost.crl";
    public string CRLDeltaRSA { get; set; } = "https://crl.pki.gov.kz/nca_d_rsa.crl";
    public CrlCache crlCache { get; set; } = new CrlCache();
    public bool LoadCRLCacheOnInit { get; set; } = true;
    public bool LoadCACertsOnInit { get; set; } = true;
}

public class CrlCache
{
    public string CRLCachePathGOST { get; set; }
    public string CRLCachePathRSA { get; set; }
    public string CRLCachePathDeltaGOST { get; set; }
    public string CRLCachePathDeltaRSA { get; set; }
    public DateTime CRLCacheValidUntil { get; set; }
    public TimeSpan CRLCacheDuration { get; set; } = new TimeSpan(hours:0, minutes:60, seconds:0);
}

public record OptionCert(string URL, KCCertType Type);

public enum KCCertType
{
    KCCertTypeCA = 513,
    KCCertTypeIntermediate = 514,
    KCCertTypeUser = 516     
}

public enum KCStoreType
{
    KCStoreTypePKCS12 = 1, // Файловая система
    KCStoreTypeKZIDCard = 2, // Удостоверение личности гражданина РК
    KCStoreTypeKazToken = 4, // Казтокен
    KCStoreTypeEToken = 8, // eToken 72k
    KCStoreTypeJaCarta = 16, // JaCarta
    KCStoreTypeX509Cert = 32, // Сертификат X509
    KCStoreTypeAKey = 64, // aKey
    KCStoreTypeEToken5110 = 128, // eToken 5110
}


public enum KCFlag
{
    KCFlagSignDraft = 1, // Сырая подпись (draft sign)
    KCFlagSignCMS = 2, // Подпись в формате CMS
    KCFlagInPEM = 4, // Входные данные в формате PEM
    KCFlagInDER = 8, // Входные данные в кодировке DER
    KCFlagInBase64 = 16, // Входные данные в кодировке BASE64
    KCFlagIn2Base64 = 32, // Дополнительные входные данные в кодировке BASE64
    KCFlagDetachedData = 64, // Отсоединенная подпись
    KCFlagWithCert = 128, // Вложить сертификат в подпись
    KCFlagWithTimestamp = 256, // Добавить в подпись метку времени
    KCFlagOutPEM = 512, // Выходные данные в формате PEM
    KCFlagOutDER = 1024, // Выходные данные в кодировке DER
    KCFlagOutBase64 = 2048, // Выходные данные в кодировке BASE64
    KCFlagProxyOff = 4096, // Отключить использование прокси-сервера и стереть настройки.
    KCFlagProxyOn = 8192, // Включить и установить настройки прокси-сервера (адрес и порт)
    KCFlagProxyAuth = 16384, // Прокси-сервер требует авторизацию (логин/пароль)
    KCFlagInFile = 32768, // Использовать, если параметр inData/outData содержит абсолютный путь к файлу

    KCFlagNoCheckCertTime =
        65536, // Не проверять срок действия сертификата при построении цепочки до корневого (для проверки старых подписей с просроченным сертификатом)
    KCFlagHashSHA256 = 131072, // Алгоритм хеширования sha256
    KCFlagHashGOST95 = 262144, // Алгоритм хеширования Gost34311_95
}

[StructLayout(LayoutKind.Sequential)]
public struct FunctionsType
{
    public IntPtr stKCFunctionsType;
}

