#include "Header.h"

int decrypt() {

    /*
    ϳ��������� �� ����������������
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
    ³������� �������� ������� �����������
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
        printf("��������� ������� ������� MY!");
    }

    /*
    ��������� ��������� �� �� ����������
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
        printf("Certificate was found!\n");
    }
    else
    {
        printf("Certificate was NOT found!\n.");
    }

    /*
    ������� �� ����������� �������� ���������� �����
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
        cout << "Error getting private context.\n";
        getchar();
        return 1;
    }

    /*
    ������� �������� ����
    */
    if (!CryptGetUserKey(hProv, keySpec, &hPrivateKey))
    {
        cout << "Error getting private key.\n";
        getchar();
        return 1;
    }

    /*
    ���������� ���������� �����
    */
    FILE* in, * inkey, * key_lenght, * encrypted;
    DWORD dwBlobLenght;
    if ((inkey = fopen("text_inKey.txt", "rb")) == NULL) {
        exit(1);
    }
    if ((key_lenght = fopen("key_length.txt", "r")) == NULL) {
        exit(1);
    }

    fscanf_s(key_lenght, "%d", &dwBlobLenght);
    fclose(key_lenght);

    /*
    ����������� ���'��� ��� �������� �����
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
        return 1;
    }
    
    /*
    ������� ������� ���� �� ����� in
    */
    if (fread(ppbKeyBlob, sizeof byte, dwBlobLenght, inkey))
    {
        printf("the session key has been read to the file\n");
    }
    else
    {
        printf("the session key could not be read from the file\n");
        getchar();
        return 1;
    }

    /*
    ��������� ������� ���� �� ��������� ��������� ����� ������������� ���������
    */
    HCRYPTKEY hSessionKey;
    if (CryptImportKey(hProv, ppbKeyBlob, dwBlobLenght, hPrivateKey, 0,
        &hSessionKey))
    {
        printf(" the key has been imported.\n");
        CryptDestroyKey(hPrivateKey); //������� �������
        free(ppbKeyBlob);
    }
    else
    {
        printf("the session key import failed.\n");
        getchar();
        return 1;
    }

    //�������� ������
    fclose(inkey);

    /*
    ���������� �� ����� �����������
    */
    if ((encrypted = fopen("text_encrypted.txt", "rb")) == NULL) {
        exit(1);
    }
    if ((in = fopen("Crypto_end.txt", "wb")) == NULL) {
        exit(1);
    }

    /*
    ��������� ����� ����������� ������
    */
    DWORD buflen = BLOCK_SIZE;
    BOOL bRes = CryptEncrypt(hSessionKey, 0, TRUE, 0, NULL, &buflen, 0);
    BYTE* pCryptBuf = (BYTE*)malloc(buflen);
    int t = 0;

    /*
    ������������ ����
    */
    while ((t = fread(pCryptBuf, sizeof byte, buflen, encrypted)))
    {
        buflen = t;
        bRes = CryptDecrypt(hSessionKey, 0, TRUE, 0, pCryptBuf, &buflen);
        if (!bRes)
        {
            cout << "CryptEncrypt (buffer size) failed, " << endl;
            getchar();
            return 1;
        }
        fwrite(pCryptBuf, sizeof byte, buflen, in);
    }
    cout << "File decryption completed successfully" << endl;

    // �������� ������
    fclose(in);
    fclose(encrypted);

    // ��������� ��������� ��������� ������
    CryptDestroyKey(hSessionKey);
    CryptReleaseContext(hProv, 0);

    return 0;
}