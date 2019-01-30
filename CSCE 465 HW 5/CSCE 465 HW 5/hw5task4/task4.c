#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

void getHash(char * hashname, char *msg, unsigned char *md_value) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	int md_len, i;
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(hashname);
	if(!md) {
		printf("Bad message digest %s\n", hashname);
		exit(1);
	}
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, msg, strlen(msg));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);
}

void setRndStr(char *msg) {
	int i;
	for (i=0;i<11;i++)
		msg[i] = rand()%256-128;
}

int crackOneWayHash(char * hashname) {
	char msg1[11], msg2[11];
	unsigned char digt1[EVP_MAX_MD_SIZE], digt2[EVP_MAX_MD_SIZE];
	int count=0, i;
	setRndStr(msg1);
	getHash(hashname, msg1, digt1);
	do {
		setRndStr(msg2);
		getHash(hashname, msg2, digt2);
		count++;
	} while (strncmp(digt1, digt2, 3)!=0);

	printf("One-way property cracked after %d tries! Same digest ", count, msg1, msg2);
	for(i = 0; i < 3; i++) printf("%02x", digt1[i]);
	printf("\n");
	return count;
}

int crackCollisionHash(char * hashname) {
	char msg1[11], msg2[11];
	unsigned char digt1[EVP_MAX_MD_SIZE], digt2[EVP_MAX_MD_SIZE];
	int count=0, i;
	do {
		setRndStr(msg1);
		getHash(hashname, msg1, digt1);
		setRndStr(msg2);
		getHash(hashname, msg2, digt2);
		count++;
	} while (strncmp(digt1, digt2, 3)!=0);

	printf("Collision after %d tries! Same digest ", count);
	for(i = 0; i < 3; i++) printf("%02x", digt1[i]);
	printf("\n");
	return count;
}
main(int argc, char *argv[])
{
	char *hashname;
	if(!argv[1])
		printf("Invalid arguments");
	else
		hashname = argv[1];
	srand((int)time(0));	// seed for RNG
	int i,count;
	for (i=0,count=0;i<15;i++)
		count+=crackCollisionHash(hashname);
	printf("Average number of attempts cracking collision-free property: %d \n", count/15);
	for (i=0,count=0;i<5;i++)
		count+=crackOneWayHash(hashname);
	printf("Average number of attempts cracking one-way property: %d \n", count/5);
}
