#include "Header.h"

int verify() {
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

	HCERTSTORE hStoreHandle;

	if (!(hStoreHandle = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		//CERT_SYSTEM_STORE_LOCAL_MACHINE,
		CERT_STORE_NAME)))
	{
		printf("no open MY.");
	}
	else
	{
		printf("Open MY\n");
	}

	// Открываем хранилище сертификатов
	HCERTSTORE hStore;

	if (!(hStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		CERT_STORE_NAME)))
	{
		printf("Нельзя открыть хранилище MY ");

	}

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

	// Импортируем public key для последующей верификации подписи или шифрования сеансового ключа
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

	FILE* signature, * in;
	DWORD dwBlobLenght;

	if ((signature = fopen("Sign.txt", "rb")) == NULL) {
		exit(1);
	}

	if ((in = fopen("Crypto.txt", "rb")) == NULL) {
		exit(1);
	}

	fseek(in, 0, SEEK_END);
	dwBlobLenght = ftell(in);
	fseek(in, 0, SEEK_SET);

	//открываем файл, содержимое которого подписываем и дальше создаем дайджест
	HCRYPTHASH hHash;
	//создаем хеш-объект
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		cout << "CryptCreateHash";
		return 1;
	}

	//чтение файла
	BYTE* read = new BYTE[dwBlobLenght + 8];
	if (fread(read, sizeof byte, dwBlobLenght, in))
	{
		printf("the file has been read to the file\n");
	}
	else
	{
		printf("the file could not be read from the file\n");
		return 1;
	}
	// Передача хешируемых данных хэш-объекту.
	if (!CryptHashData(hHash, read, dwBlobLenght, 0))
	{
		cout << "CryptHashData";
		return 1;
	}
	std::cout << "Hash data loaded" << std::endl;
	// Получение хеш-значения
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

	DWORD dwSignLenght = 0;

	fseek(signature, 0, SEEK_END);
	dwSignLenght = ftell(signature);
	fseek(signature, 0, SEEK_SET);

	BYTE* read1 = new BYTE[dwSignLenght];
	fread(read1, sizeof byte, dwSignLenght, signature);

	//Перевірка цифрового підписа
	BOOL result = CryptVerifySignatureW(hHash, read1, dwSignLenght, hPublicKey, NULL, 0);
	std::cout << "Check is completed" << std::endl;
	std::cout << "Check result:" << ((result) ? "Verified!" : "NOTverified!") << std::endl;

	if (result) {
		cout << "Verify true";
	}
	else
	{
		cout << "Verify false";
	}

	fclose(signature);

	CryptReleaseContext(hProv, 0);

	return 0;
}