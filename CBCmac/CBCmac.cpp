#include "Header.h"

int mac_cbc() {

    /*
    Ініціалізація змінних
    */
    HCRYPTPROV  hProv = NULL;
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
    if (!CryptAcquireContextW(&hProv, NULL, 0, PROV_RSA_FULL, 0) &&
        !CryptAcquireContextW(&hProv, NULL, 0, PROV_RSA_FULL, CRYPT_NEWKEYSET))
    {
        puts("NO create keyset\n");
        return -1;
    }
    else
    {
        puts("YES, create keyset\n");
    }

    /*
    Зчитування файлів
    */
    FILE* password, * out, * in, * inkey, * key_lenght;
    DWORD dwBlobLenght = 0;
    DWORD dwBlobLenght1 = 0;

    if ((password = fopen("password.txt", "rb")) == NULL) {
        exit(1);
    }
    if ((in = fopen("Crypto.txt", "rb")) == NULL) {
        exit(1);
    }
    if ((out = fopen("CBC_MAC_3DES.txt", "wb")) == NULL) {
        exit(1);
    }

    fseek(password, 0, SEEK_END);
    dwBlobLenght = ftell(password);
    fseek(password, 0, SEEK_SET);

    BYTE* read = new BYTE[dwBlobLenght];
    fread(read, sizeof byte, dwBlobLenght, password);

    HCERTSTORE hStore;

    /*
    Відкриття власного сховища сертифікатів
   */
    if (!(hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER,
        //CERT_SYSTEM_STORE_LOCAL_MACHINE,
        CERT_STORE_NAME)))
    {
        printf("Not open MY.");
    }
    else
    {
        printf("Open MY\n");
    }

    /*
    Отримання вказівника на мій сертифікат
    */
    PCCERT_CONTEXT pSignerCert = 0;
    if (pSignerCert = CertFindCertificateInStore(
        hStore,
        MY_TYPE,
        0,
        CERT_FIND_SUBJECT_STR,
        SIGNER_NAME,
        NULL))
    {
        printf("Certificate was found !\n");
    }
    else
    {
        printf("Certificate was NOT found!!!\n.");
    }

    /*
    Імпорт "public key" для наступної верифікації підпису або шифрування сесійного ключа
    */
    HCRYPTKEY hPublicKey;
    if (CryptImportPublicKeyInfo(
        hProv,
        MY_TYPE,
        &(pSignerCert->pCertInfo->SubjectPublicKeyInfo),
        &hPublicKey))
    {
        printf("Import public key.\n");
    }
    else
    {
        printf("Ошибка CryptAcquireContext.");
    }

    HCRYPTKEY hSessionKey;

    /*
    Генерація сесійного ключа. Мій ключ - 3DES. Режим - СВС
    */
    if (!CryptGenKey(hProv, CALG_3DES_112,
        CRYPT_ENCRYPT | CRYPT_DECRYPT, &hSessionKey))
    {
        printf("Error CryptGenKey");
        return -1;
    }

    std::cout << "Session key generated" << std::endl;

    /*
    Встановлення режиму шифрування повідомлення - СВС
    */
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

    /*
    Визначення розміра необхідного буфера
    */
    buflen = BLOCK_SIZE;
    if (!CryptEncrypt(hSessionKey, 0, TRUE, 0, NULL, &buflen, 0))
    {
        cout << " Crypt Encrypt (bufSize) failed." << endl;
        getchar();
        return -1;
    }

    /*
    Видідення пам'яті під буфер
    */
    pCryptBuf = (BYTE*)malloc(buflen);
    int t = 0;

    /*
    Шифрування фaйлу "in"
    */
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
    for (DWORD i = 0; i < buflen; i++) printf("%2.2x ", pCryptBuf[i]);
    cout << endl;

    // Print the hash to the file.
    if (fwrite(pCryptBuf, sizeof(char), buflen, out))
    {
        printf("the hash has been written to the file\n");
    }

    if ((inkey = fopen("inkey.txt", "wb")) == NULL) {
            exit(1);
    }

    /*
    Визначаємо розмір Bloba сесійного ключа
    */
    dwBlobLenght = 0;
    if (CryptExportKey(hSessionKey, hPublicKey, SIMPLEBLOB, 0, 0, &dwBlobLenght))
    {
        printf("size of the Blob");
    }
    else
    {
        printf("error computing Blob length");
        getchar();
        return -1;
    }
    
    /*
    Розподіляємо пам'ять для сесійного ключа
    */
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
    
    /*
    Зашифруємо сесійний ключ hKey відкритим ключем hPublicKey
    */
    if (CryptExportKey(hSessionKey, hPublicKey, SIMPLEBLOB, 0, ppbKeyBlob, &dwBlobLenght))
    {
        printf("contents have been written to the Blob");
    }
    else
    {
        printf("Could not get exporting key.");
        free(ppbKeyBlob);
        ppbKeyBlob = NULL;
        getchar();
        return -1;
    }

    /*
    Запис hSessionKey
    */
    if (fwrite(ppbKeyBlob, sizeof byte, dwBlobLenght, inkey))
    {
        printf("the session key has been written to the file\n");
        free(ppbKeyBlob);
    }
    else
    {
        printf("the session key could not be written to the file\n");
        getchar();
        return -1;
    }

    fclose(inkey);

    /*
    Запис hSessionKey у новий файл
    */
    if ((key_lenght = fopen("key_length.txt", "w")) == NULL) {//b-побитово
        puts("Cannot open file key.");
        exit(1);
    }
    fprintf(key_lenght, "%d\n", dwBlobLenght);
    fclose(key_lenght);

    fclose(in);
    fclose(out);

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
