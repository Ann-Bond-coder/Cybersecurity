#include "Header.h";

int cbcvr() {
;
    HCRYPTHASH  hHash = NULL;
    HCRYPTKEY   hKey = NULL;
    PBYTE       pbHash = NULL;
    DWORD       dwDataLen = 0;

    HCRYPTHASH  hHmacHash = NULL;
    BYTE        Data2[] = { 0x6D,0x65,0x73,0x73,0x61,0x67,0x65 };
    HMAC_INFO   HmacInfo;

    /*
    Підключення до криптопровайдера
    */
    HCRYPTPROV hProv = NULL;
    if (!CryptAcquireContextW(&hProv, NULL, 0, PROV_RSA_FULL, 0) &&
        !CryptAcquireContextW(&hProv, NULL, 0, PROV_RSA_FULL, CRYPT_NEWKEYSET))
    {
        puts("NO create keyset\n");
        return 1;
    }
    else
    {
        puts("YES, create keyset\n");
    }

    /*
    Відкриття власного сховища сертифікатів
    */
    HCERTSTORE hStore;
    HCERTSTORE hStoreHandle;

    if (!(hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER,
        //CERT_SYSTEM_STORE_LOCAL_MACHINE, //якщо на локальній машині
        CERT_STORE_NAME)))
    {
        printf("Неможливо відкрити сховище MY!");
    }

    FILE* password, * in;
    DWORD dwBlobLenght = 0;
    DWORD dwBlobLenght1 = 0;

    if ((password = fopen("password.txt", "rb")) == NULL) {
        exit(1);
    }
    if ((in = fopen("Crypto.txt", "rb")) == NULL) {
        exit(1);
    }

    fseek(password, 0, SEEK_END);
    dwBlobLenght = ftell(password);
    fseek(password, 0, SEEK_SET);

    BYTE* read = new BYTE[dwBlobLenght];
    fread(read, sizeof byte, dwBlobLenght, password);

    FILE* fhmac;
    if ((fhmac = fopen("CBC_MAC_3DES.txt", "rb")) == NULL) {
        exit(1);
    }

    fseek(fhmac, 0, SEEK_END);
    DWORD dwBlobLenght2 = ftell(fhmac);
    fseek(fhmac, 0, SEEK_SET);

    BYTE* pbHashCmp = new BYTE[dwBlobLenght2];
    fread(pbHashCmp, sizeof byte, dwBlobLenght2, fhmac);
    bool ok = true;

    // Получаем указатель на наш сертификат
    PCCERT_CONTEXT pSignerCert = 0;

    if (pSignerCert = CertFindCertificateInStore(
        hStore,
        MY_TYPE,
        0,
        CERT_FIND_SUBJECT_STR,
        SIGNER_NAME,
        NULL))
    {
        printf("Certificate was found !!!!!\n");
    }
    else
    {

        printf("Certificate was NOT found!!!\n.");
    }

    HCRYPTKEY hPrivateKey = 0;
    DWORD keySpec = 0;
    // Извлекаем из сертификата контекст приватного ключа   
    if (!CryptAcquireCertificatePrivateKey(
        pSignerCert,
        0,
        NULL,
        &hProv,
        &keySpec,
        NULL))
    {
        cout << "Error getting private context\n";
        getchar();
        return -1;
    }

    //   Извлекаем закрытый ключ 
    if (!CryptGetUserKey(hProv, keySpec, &hPrivateKey))
    {
        cout << "Error getting private key\n";
        getchar();
        return -1;
    }

    dwBlobLenght = 0;
    HCRYPTKEY hSessionKey;
    FILE* inkey, * key_lenght;
    if ((inkey = fopen("inkey.txt", "rb")) == NULL) {
        exit(1);
    }
    if ((key_lenght = fopen("key_length.txt", "rb")) == NULL) {
        exit(1);
    }

    fscanf_s(key_lenght, "%d", &dwBlobLenght);

    fclose(key_lenght);

    //Распределяем память для сессионного ключа
    BYTE* ppbKeyBlob;
    ppbKeyBlob = NULL;
    if (ppbKeyBlob = (LPBYTE)malloc(dwBlobLenght))
    {
        printf("memory has been allocated for the Blob");
    }
    else
    {
        printf("Error memory for key length!!!");
        getchar();
        return -1;
    }
    //Считываем сессионный  ключ из файла inkey.
    if (fread(ppbKeyBlob, sizeof byte, dwBlobLenght, inkey))
    {
        printf("the session key has been read to the file\n");
    }
    else
    {
        printf("the session key could not be read from the file\n");
        getchar();
        return -1;
    }

    fclose(inkey);

    //Импортируем сессионный ключ с помощью закрытого ключа ассиметричного алгоритма
    hSessionKey = 0;
    if (CryptImportKey(hProv, ppbKeyBlob, dwBlobLenght, hPrivateKey, 0,
        &hSessionKey))
    {
        printf(" the key has been imported.\n");
        CryptDestroyKey(hPrivateKey); //очищаем ресурсы
        free(ppbKeyBlob);
    }
    else
    {
        printf("the session key import failed.\n");
        getchar();
        return -1;
    }


    // Устанавливаем режим шифрования сообщения CBC

    DWORD dwMode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hSessionKey, KP_MODE, (BYTE*)&dwMode, 0))
    {
        puts("Error CryptSetKeyParam!\n");
        return -1;
    }

    BYTE* pCryptBuf = 0;
    DWORD   buflen;
    BOOL      bRes;
    DWORD    datalen;

    // Определяем размер буфера необходимого для блоков длины BLOCK SIZE 
    buflen = BLOCK_SIZE;
    if (!CryptEncrypt(hSessionKey, 0, TRUE, 0, NULL, &buflen, 0))
    {
        cout << " Crypt Encrypt (bufSize) failed." << endl;
        getchar();
        return -1;
    }

    //Выделим память под буфер
    pCryptBuf = (BYTE*)malloc(buflen);
    int t = 0;

    //   Шифруем файл in
    while ((t = fread(pCryptBuf, sizeof byte, BLOCK_SIZE, in)))
    {
        datalen = t;
        bRes = CryptEncrypt(hSessionKey, 0, TRUE, 0, pCryptBuf, &datalen, buflen);
        if (!bRes) {
            cout << "CryptEncrypt (encryption) failed, " << endl;
            getchar(); 
            return -1;
        }
    }

    cout << "MAC CBC: ";
    for (DWORD i = 0; i < buflen; i++)  printf("%2.2x ", pCryptBuf[i]);
    cout << endl;

    if (dwBlobLenght2 == buflen) {
        for (DWORD i = 0; i < dwBlobLenght2; i++)
        {
            if (pbHashCmp[i] != pCryptBuf[i]) {
                ok = false;
                break;
            }
        }
    }
    else {
        ok = false;
    }

    if (ok) cout << "Matched, verify YES";
    else cout << "Do not match, verify NO";

    fclose(in);
    fclose(fhmac);

ErrorExit:
    if (hHmacHash)
        CryptDestroyHash(hHmacHash);
    if (hKey)
        CryptDestroyKey(hKey);
    if (hHash)
        CryptDestroyHash(hHash);
    if (hProv)
        CryptReleaseContext(hProv, 0);
    if (pbHash)
        free(pbHash);
    if (hProv)
        CryptReleaseContext(hProv, 0);
}