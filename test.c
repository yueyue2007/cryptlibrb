#include "cryptlib.h"
#include <stdio.h>
#include <stdlib.h>

int  main(void)
{
	cryptInit();
	cryptAddRandom(NULL,CRYPT_RANDOM_SLOWPOLL);
	printf("Hello,cryptlib!\n");

	CRYPT_ENVELOPE cryptEnvelope,cryptEnvelope2;
	int bytesCopied,status,bytesCopied2;
	char *envelopedData,*uncompressData;

	/* create the envelope */
	status = cryptCreateEnvelope(&cryptEnvelope,CRYPT_UNUSED,CRYPT_FORMAT_CRYPTLIB);
	if (!cryptStatusOK(status))
	{
		printf("create envelope failed!");
		return 0;
	}
	char a[] = "34534653465";
	status =cryptSetAttributeString(cryptEnvelope,CRYPT_ENVINFO_PASSWORD,"1234",4);
	status =cryptPushData(cryptEnvelope,a,sizeof(a),&bytesCopied);
	status = cryptFlushData(cryptEnvelope);
	envelopedData = (char*)malloc(200);
	status = cryptPopData(cryptEnvelope,envelopedData,200,&bytesCopied);
	//envelopedData[bytesCopied] = '\0';

	cryptDestroyEnvelope(cryptEnvelope);

	/* deenvelop data */
	
	status = cryptCreateEnvelope(&cryptEnvelope2,CRYPT_UNUSED,CRYPT_FORMAT_AUTO);
	
	status = cryptPushData(cryptEnvelope2,envelopedData,bytesCopied,&bytesCopied2);
	status =cryptSetAttributeString(cryptEnvelope2,CRYPT_ENVINFO_PASSWORD,"1234",4);
	status = cryptFlushData(cryptEnvelope2);

	uncompressData = (char*) malloc(40);
	status = cryptPopData(cryptEnvelope2,uncompressData,40,&bytesCopied2);
	printf("the data is %s\n",uncompressData);


	
	cryptDestroyEnvelope(cryptEnvelope2);
	cryptEnd();
}