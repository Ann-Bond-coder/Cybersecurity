#include "Header.h"

int sign() {

    /*
    Підключення до криптопровайдера
    */
    HCRYPTPROV hProv = NULL;
    LPTSTR      pszName = NULL;
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
    HCERTSTORE hStoreHandle;
    HCERTSTORE hStore;
    if (!(hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER,
        CERT_STORE_NAME)))
    {
        printf("No open MY.");
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
        printf("Certificate was found !!!!!\n");
    }
    else
    {
        printf("Certificate was NOT found!!!\n.");
    }

    /*
    Імпорт "private key" для наступної верифікації підпису або шифрування сесійного ключа
    */
    HCRYPTKEY hPrivateKey;
    DWORD keySpec = 0;  
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
        return 1;
    }

    /*
    Вилучаємо закритий ключ
    */
    if (!CryptGetUserKey(hProv, keySpec, &hPrivateKey))
    {
        cout << "Error getting private key\n";
        getchar();
        return 1;
    }

    /*
    Зчитування файлу
    */
    FILE* in, * ink;
    DWORD dwBlobLenght;
    if ((in = fopen("Crypto.txt", "rb")) == NULL) {
        exit(1);
    }

    fseek(in, 0, SEEK_END);
    dwBlobLenght = ftell(in);
    fseek(in, 0, SEEK_SET);

    /*
    Відкриваємо файл, вміст якого підписуємо і далі створюємо дайджест
    */
    HCRYPTHASH hHash;

    //створюємо хеш-об'єкт
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        cout << "CryptCreateHash";
        return 1;
    }

    //читання файла
    BYTE* read = new BYTE[dwBlobLenght + 8];
    if (fread(read, sizeof byte, dwBlobLenght, in))
    {
        printf("the file has been read to the file\n");
    }
    else
    {
        printf("the file could not be read from the file\n");
        return -1;
    }

    //Передача даних, що хешуються, хеш-об'єкту
    if (!CryptHashData(hHash, read, dwBlobLenght, 0))
    {
        cout << "CryptHashData";
        return 1;
    }
    std::cout << "Hash data loaded" << std::endl;

    //Отримання хеш-значення
    DWORD count = 0;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &count, 0))
    {
        cout << "CryptGetHashParam";
        return 1;
    }

    char* hash_value = static_cast<char*>(malloc(count + 1));
    ZeroMemory(hash_value, count + 1);

    if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)hash_value, &count, 0))
    {
        cout << "CryptGetHashParam";
        return 1;
    }
    std::cout << "Hash value is received" << std::endl;

    fclose(in);

    count = 0;
    if (!CryptSignHash(hHash, 1, NULL, 0, NULL, &count))
    {
        cout << "CryptSignHash";
        return 1;
    }

    char* sign_hash = static_cast<char*>(malloc(count + 1));

    ZeroMemory(sign_hash, count + 1);

    if (!CryptSignHashW(hHash, 1, NULL, 0, (BYTE*)sign_hash, &count))
    {
        cout << "CryptSignHash";
        return 1;
    }
    std::cout << "Signature created" << std::endl;

    //Запис у файл
    FILE* out;
    if ((out = fopen("Sign.txt", "wb")) == NULL) {
        exit(1);
    }

    if (fwrite(sign_hash, sizeof(char), count, out))
    {
        printf("the session key has been written to the file\n");
        free(sign_hash);
    }

    fclose(out);

    CryptReleaseContext(hProv, 0);

    return 0;
}