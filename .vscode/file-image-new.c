#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
#include<winnt.h>


int main(int argc, char* argv[])
{
	FILE* pfile = NULL;
    FILE* pWrite = NULL;
	int filesize = 0;
    int headersize = 0;

	LPVOID pFileBuffer = NULL;
    LPVOID pImageBuffer = NULL;
    LPVOID pNewBuffer = NULL;

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    
    pfile = fopen("C:\\WINDOWS\\notepad.exe","rb");
    if (pfile == NULL)
    {
        printf("file open error");
        fclose(pfile);
        return 0;
    }
    fseek(pfile,0,SEEK_END);
    filesize = ftell(pfile);
    fseek(pfile,0,SEEK_SET);
    pFileBuffer = malloc(filesize);
    if (pFileBuffer == NULL)
    {
        printf("memory add error");
        fclose(pfile);
        free(pFileBuffer);
        return 0;
    }
    memset(pFileBuffer,0,filesize);
    fread(pFileBuffer,1,filesize,pfile);

    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

    pImageBuffer = malloc(pOptionHeader->SizeOfImage);
    if (pImageBuffer == NULL)
    {
        printf("pImageBuffer add memory error");
        fclose(pfile);
        free(pFileBuffer);
        free(pImageBuffer);
        return 0;
    }
    memset(pImageBuffer,0,pOptionHeader->SizeOfImage);
    memcpy(pImageBuffer,pFileBuffer,pOptionHeader->SizeOfHeaders);

    for (size_t i = 0; i < pPEHeader->NumberOfSections; i++)
    {
        memcpy
		(
			(void *) ( (char *)pImageBuffer + pSectionHeader[i].VirtualAddress),
 
			(void * ) ((char *)pDosHeader + pSectionHeader[i].PointerToRawData),
 
			pSectionHeader[i].SizeOfRawData
		);
    }

    pNewBuffer = malloc(pOptionHeader->SizeOfImage);
    if (pNewBuffer == NULL)
    {
       printf("NewBuffer memory error");
       fclose(pfile);
       free(pFileBuffer);
       free(pImageBuffer);
       free(pNewBuffer);
       return 0;
    }
    memset(pNewBuffer,0,pOptionHeader->SizeOfImage);
    memcpy(pNewBuffer,pImageBuffer,pOptionHeader->SizeOfHeaders);
    for (size_t i = 0; i < pPEHeader->NumberOfSections; i++)
    {
        memcpy
        (
			(void * ) ( (char *)pNewBuffer + pSectionHeader[i].PointerToRawData ) ,
 
			 (void * )((char *)pImageBuffer  + pSectionHeader[i].VirtualAddress),
			pSectionHeader[i].SizeOfRawData
		);
    }

    pWrite = fopen("D:\\desktop\\notepad.exe","wb");
    fwrite(pNewBuffer,1,filesize,pWrite);

    fclose(pWrite);
    fclose(pfile);
    free(pFileBuffer);
    free(pImageBuffer);
    free(pNewBuffer);
    return 0;

}
