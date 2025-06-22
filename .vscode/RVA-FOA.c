#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
#include<winnt.h>

int main(int argc, char* argv[])
{
    
    FILE* pfile = NULL;
    LPVOID pFileBuffer = NULL;
    LPVOID pImageBuffer = NULL;

    PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

    int ImageAddress,FileAddress;
    ImageAddress = 74627;

    pfile = fopen("C:\\WINDOWS\\notepad.exe","rb");
    if (pfile == NULL)
    {
        printf("file open error");
        fclose(pfile);
        return 0;
    }
    fseek(pfile,0,SEEK_END);
    int filesize = ftell(pfile);
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

    int t = ImageAddress - (int)pImageBuffer;
    int x = 0;
    int temp = 0;
    for (size_t i = 0; i < pPEHeader->NumberOfSections; i++)
    {
        if (t > (int)(pSectionHeader[i].VirtualAddress) && t < (int)(pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize))
        {
            temp = ImageAddress - (int)(pSectionHeader[i].VirtualAddress);
            FileAddress = (int)(pSectionHeader[x].PointerToRawData) + temp;
            printf("%x",FileAddress);
            break;
        }
        else
        {
            return 0;
        }
        x++;
    }
    if (x >= pPEHeader->NumberOfSections)
    {
        printf("error");
    }
    

    free(pFileBuffer);
    free(pImageBuffer);
    fclose(pfile);
    return 0;
}