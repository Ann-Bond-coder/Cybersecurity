#include "Header.h"

int encrypt() {

	/*
	ϳ��������� �� ����������������
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
	³������� �������� ������� �����������
	*/
	HCERTSTORE hStore;
	HCERTSTORE hStoreHandle;
	if (!(hStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		//CERT_SYSTEM_STORE_LOCAL_MACHINE, //���� �� �������� �����
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
		printf("Error CryptAcquireContext.");
	}


	/*
	��������� �������� �����. ̳� ���� - Two keys 3DES OFB 
	*/
	HCRYPTKEY hSessionKey;
	if (!CryptGenKey(hProv, CALG_3DES_112,
		CRYPT_ENCRYPT | CRYPT_DECRYPT, &hSessionKey))
	{
		printf("Error CryptGenKey");
		return 1;
	}

	std::cout << "Session key generated" << std::endl;

	/*
	������������ ������ ���������� ����������� - OFB
	*/
	DWORD dwMode = CRYPT_MODE_CFB;
	if (!CryptSetKeyParam(hSessionKey, KP_MODE, (BYTE*)&dwMode, 0))
	{
		puts("Error CryptSetKeyParam!\n");
		return -1;
	}

	/*
	���������� ����� �� ����� � �����
	*/
	FILE* in, * inkey, * key_lenght, * encrypted;
	if ((in = fopen("Crypto.txt", "rb")) == NULL) {
		exit(1);
	}
	if ((encrypted = fopen("text_encrypted.txt", "wb")) == NULL) {
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
	���������� ����� "in"
	*/
	while ((t = fread(pCryptBuf, sizeof byte, BLOCK_SIZE, in)))
	{
		datalen = t;
		bRes = CryptEncrypt(hSessionKey, 0, TRUE, 0, pCryptBuf, &datalen, buflen);

		if (!bRes) {
			cout << "CryptEncrypt (encryption) failed, " << endl;
			getchar(); return -1;
		}
		fwrite(pCryptBuf, sizeof byte, datalen, encrypted);
	}
	cout << "File encryption completed successfully" << endl;

	//�������� ������
	fclose(in);
	fclose(encrypted);
	//������� ������
	free(pCryptBuf);

	if ((inkey = fopen("text_inKey.txt", "wb")) == NULL) {
		exit(1);
	}
	DWORD dwBlobLenght = 0;

	/*
	���������� ������ �������� �����
	*/
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
	����������� ���'��� ��� �������� �����
	*/
	BYTE* ppbKeyBlob;
	ppbKeyBlob = NULL;
	if (ppbKeyBlob = (LPBYTE)malloc(dwBlobLenght))
	{
		printf("Memory has been allocated for the Blob!");
	}
	else
	{
		printf("Error memory for key length!");
		getchar();
		return -1;
	}

	/*
	����� ������� ����� "hSessionKey" � ����� ���� - �������
	*/
	if ((key_lenght = fopen("key_length.txt", "w")) == NULL) {//b-��������
		puts("Cannot open file key.");
		exit(1);
	}
	fprintf(key_lenght, "%d\n", dwBlobLenght);
	fclose(key_lenght);

	/*
	��������� ������� ���� hKey �������� ������ hPublicKey
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
	�������� ������������� ���� � ���� out.
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
	��������� ��������� ��������� ������
	*/
	CryptDestroyKey(hSessionKey);
	CryptReleaseContext(hProv, 0);

	// ��� �������
	_getch();

	return 0;
}
