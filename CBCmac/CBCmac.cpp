#include "Header.h";

int cbcmac() {

	/*
	����������� ������
	*/
	HCRYPTPROV hProv = NULL;
	LPTSTR      pszName = NULL;

	/*
	ϳ��������� �� ����������������
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
		printf("������ ������� ��������� MY ");
	}
	else
	{
		printf("Open MY\n");
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
		printf("Certificate was found !!!!!\n");
	}
	else
	{
		printf("Certificate was NOT found!!!\n.");
	}

	/*
	������ "public key" ��� �������� ����������� ������ ��� ���������� �������� �����
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
		printf("������ CryptAcquireContext.");
	}

	HCRYPTKEY hSessionKey;

	/*
	��������� �������� �����. ̳� ���� - 3DES. ����� - ���
	*/
	if (!CryptGenKey(hProv, CALG_3DES_112,
		CRYPT_ENCRYPT | CRYPT_DECRYPT, &hSessionKey))
	{
		printf("Error CryptGenKey");
		return 1;
	}

	std::cout << "Session key generated" << std::endl;

	/*
	������������ ������ ���������� ����������� - ���
	*/
	DWORD dwMode = CRYPT_MODE_CBC;
	if (!CryptSetKeyParam(hSessionKey, KP_MODE, (BYTE*)&dwMode, 0))
	{
		puts("Error CryptSetKeyParam!\n");
		return -1;
	}

	/*
	���������� �� ����� � �����
	*/
	FILE* in, * cbcMacSessionKey, * cbcMAC;
	if ((in = fopen("Crypto.txt", "rb")) == NULL) {
		exit(1);
	}
	if ((cbcMAC = fopen("CBC_MAC_3DES.txt", "wb")) == NULL) {
		exit(1);
	}
	if ((cbcMacSessionKey = fopen("CBC_MAC_3DES session key.txt", "wb")) == NULL) {
		exit(1);
	}

	BYTE* pCryptBuf = 0;
	DWORD   buflen;
	BOOL      bRes;
	DWORD    datalen;

	/*
	���������� ������ ����������� ������
	*/
	buflen = BLOCK_SIZE;
	if (!CryptEncrypt(hSessionKey, 0, TRUE, 0, NULL, &buflen, 0))
	{
		cout << "Crypt Encrypt(bufSize) failed." << endl;
		getchar();
		return -1;
	}

	/*
	�������� ���'�� �� �����
	*/
	pCryptBuf = (BYTE*)malloc(buflen);
	int t = 0;

	/*
	���������� �a��� "in"
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
	cout << "File encryption completed successfully" << endl;

	fwrite(pCryptBuf, sizeof byte, datalen, cbcMAC);

	/*
	��������� ����� Bloba �������� �����
	*/
	DWORD dwBlobLenght = 0;
	if (CryptExportKey(hSessionKey, hPublicKey, SIMPLEBLOB, 0, 0, &dwBlobLenght))
	{
		printf("size of the Blob\n");
	}
	else
	{
		printf("error computing Blob length\n");
		getchar();
		return -1;
	}
	
	/*
	����������� ���'��� ��� �������� �����
	*/
	BYTE* ppbKeyBlob;
	ppbKeyBlob = NULL;
	if (ppbKeyBlob = (LPBYTE)malloc(dwBlobLenght))
	{
		printf("memory has been allocated for the Blob\n");
	}
	else
	{
		printf("Error memory for key length!!!\n");
		getchar();
		return -1;
	}

	/*
	��������� ������� ���� hKey �������� ������ hPublicKey
	*/
	if (CryptExportKey(hSessionKey, hPublicKey, SIMPLEBLOB, 0, ppbKeyBlob, &dwBlobLenght))
	{
		printf("contents have been written to the Blob\n");
	}
	else
	{
		printf("Could not get exporting key.\n");
		free(ppbKeyBlob);
		ppbKeyBlob = NULL;
		getchar();
		return -1;
	}

	/*
	����� hSessionKey
	*/
	if (fwrite(ppbKeyBlob, sizeof byte, dwBlobLenght, cbcMacSessionKey))
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

	//�������� ������
	fclose(in);
	fclose(cbcMAC);
	fclose(cbcMacSessionKey);
	//������� ������
	free(pCryptBuf);

	/*
	��������� ��������� ��������� ������
	*/
	CryptDestroyKey(hSessionKey);
	CryptReleaseContext(hProv, 0);

	// ��� �������
	_getch();

	return 0;
}