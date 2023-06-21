#include "Header.h";

int verifyHmac() {

    /*
    Ініціалізація змінних
    */
    HCRYPTPROV  hProv = NULL;
    HCRYPTHASH  hHash = NULL;
    HCRYPTKEY   hKey = NULL;
    PBYTE       pbHash = NULL;
    HCRYPTHASH  hHmacHash = NULL;
    DWORD       dwDataLen = 0;
    HMAC_INFO   HmacInfo;
    bool isVerified = true;

    /*
    Підключення до криптопровайдера
    */
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
    Зчитування секретного ключа, який створюється на основі пароля
    */
    FILE* password, * verifiedHmacFile, * originTextFile;
    DWORD dwBlobLenght;
    if ((password = fopen("password.txt", "rb")) == NULL) {
        exit(1);
    }

    //Вихідний текст
    if ((originTextFile = fopen("Crypto.txt", "rb")) == NULL) {
        exit(1);
    }

    //Згенерований Hmac
    if ((verifiedHmacFile = fopen("Hmac.txt", "rb")) == NULL) {
        exit(1);
    }

    /*
    Навігіція по файлу
    */
    fseek(password, 0, SEEK_END);
    dwBlobLenght = ftell(password);
    fseek(password, 0, SEEK_SET);

    /*
    Зчитування файлу
    */
    BYTE* read = new BYTE[dwBlobLenght];
    if (fread(read, sizeof byte, dwBlobLenght, password))
    {
        printf("the file 'password' has been read to the file\n");
    }
    else
    {
        printf("the file 'password' could not be read from the file\n");
        return 1;
    }

    /*
    Навігіція по файлу
    */
    DWORD Lenght = 0;
    fseek(originTextFile, 0, SEEK_END);
    Lenght = ftell(originTextFile);
    fseek(originTextFile, 0, SEEK_SET);

    /*
    Зчитування файлу
    */
    BYTE* text = new BYTE[Lenght];
    if (fread(text, sizeof byte, Lenght, originTextFile))
    {
        printf("the original text has been read to the file\n");
    }
    else
    {
        printf("the original text could not be read from the file\n");
        return 1;
    }

    DWORD hmacFilelenght = 0;
    fseek(verifiedHmacFile, 0, SEEK_END);
    hmacFilelenght = ftell(verifiedHmacFile);
    fseek(verifiedHmacFile, 0, SEEK_SET);

    BYTE* readed_hmac = new BYTE[hmacFilelenght];
    if (fread(readed_hmac, sizeof byte, hmacFilelenght, verifiedHmacFile))
    {
        printf("the hmac file has been read to the file\n");
    }
    else
    {
        printf("the hmac file could not be read from the file\n");
        return 1;
    }

    /*
    Створення ключа хешування
    */
    if (!CryptCreateHash(
        hProv,
        CALG_SHA1,
        0,
        0,
        &hHash))
    {
        printf("Error in CryptCreateHash 0x%08x \n", GetLastError());
        goto ErrorExit;
    }

    if (!CryptHashData(
        hHash,
        read,
        dwBlobLenght,
        0))
    {
        printf("Error in CryptHashData 0x%08x \n",
            GetLastError());
        goto ErrorExit;
    }

    if (!CryptDeriveKey(
        hProv,
        CALG_RC4,
        hHash,
        0,
        &hKey))
    {
        printf("Error in CryptDeriveKey 0x%08x \n", GetLastError());
        goto ErrorExit;
    }

    //Закриття потоків
    fclose(password);

    /*
    Обнулення структури HMAC_INFO і використовувати алгоритм хешування MD2.
    */
    ZeroMemory(&HmacInfo, sizeof(HmacInfo));
    HmacInfo.HashAlgid = CALG_MD2;

    /*
    Створення хеш-об'єкту
    */
    if (!CryptCreateHash(
        hProv,
        CALG_HMAC,
        hKey,
        0,
        &hHmacHash))
    {
        printf("Error in CryptCreateHash 0x%08x \n",
            GetLastError());
        goto ErrorExit;
    }

    if (!CryptSetHashParam(
        hHmacHash,
        HP_HMAC_INFO,    //алгоритм  
        (BYTE*)&HmacInfo,
        0))
    {
        printf("Error in CryptSetHashParam 0x%08x \n",
            GetLastError());
        goto ErrorExit;
    }

    if (!CryptHashData(
        hHmacHash,
        text,     //повідомлення
        Lenght,
        0))
    {
        printf("Error in CryptHashData 0x%08x \n",
            GetLastError());
        goto ErrorExit;
    }

    /*
    Виділення пам'яті та отримання HMAС
    */
    if (!CryptGetHashParam(
        hHmacHash,
        HP_HASHVAL,
        NULL,
        &dwDataLen,
        0))
    {
        printf("Error in CryptGetHashParam 0x%08x \n",
            GetLastError());
        goto ErrorExit;
    }

    pbHash = (BYTE*)malloc(dwDataLen);
    if (NULL == pbHash)
    {
        printf("unable to allocate memory\n");
        goto ErrorExit;
    }

    if (!CryptGetHashParam(
        hHmacHash,
        HP_HASHVAL,
        pbHash,
        &dwDataLen,
        0))
    {
        printf("Error in CryptGetHashParam 0x%08x \n", GetLastError());
        goto ErrorExit;
    }

    /*
    Вивести хеш на консоль.
    */
    // Print the hash to the console.
    printf("The verify hash is:  \n");
    for (DWORD i = 0; i < dwDataLen; i++)
    {
        printf("%2.2x ", readed_hmac[i]);
    }
    printf("\n");

    // Print the hash to the console.
    printf("The hash is:  \n");
    for (DWORD i = 0; i < dwDataLen; i++)
    {
        printf("%2.2x ", pbHash[i]);
    }
    printf("\n");
    fwrite(pbHash, sizeof byte, dwDataLen, verifiedHmacFile);

    for (DWORD i = 0; i < dwDataLen; i++)
    {
        if (pbHash[i] != readed_hmac[i]) {
            isVerified = false;
        }
    }
    if (isVerified)
        printf("\nHmac has been verified\n");
    else
        printf("\nHmac has not been verified\n");

    //Закриття потоків
    fclose(originTextFile);
    fclose(verifiedHmacFile);

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
    return 0;
}