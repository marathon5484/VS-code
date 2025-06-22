
#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
#include<winnt.h>


int main(int argc, char* argv[])
{
	FILE* pfile = NULL;
	int filesize = 0;
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	BYTE a[9] = {0};
	int i,j;
	
	pfile = fopen("C:\\WINDOWS\\notepad.exe","rb");
	if(!pfile)
	{
		fclose(pfile);
		return 0;
	}
	fseek(pfile,0,SEEK_END);
	filesize = ftell(pfile);
	fseek(pfile,0,SEEK_SET);
	pFileBuffer = malloc(filesize);
	if(!pFileBuffer)
	{
		printf("space error");
		fclose(pfile);
		free(pFileBuffer);
		return 0;
	}
	fread(pFileBuffer,1,filesize,pfile);
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("file is not .exe");
		return 0;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pNTHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	for(i=0;i<pPEHeader->NumberOfSections;i++)
	{
		printf("*****************************NUM. %d Section*************************",i+1);
		for(j=0;j<8;j++)
		{
			a[j]=pSectionHeader->Name[j];
		}
		a[8]='\0';
		j=0;
		while(a[j])
		{
			printf("%x",a[j]);
			j++;
		}
		printf("\n");
		printf("Misc:%x\n",pSectionHeader->Misc);
		printf("VirtualAddress:%x\n",pSectionHeader->VirtualAddress);
		printf("SizeOfRawData:%x\n",pSectionHeader->SizeOfRawData);
		printf("PointerToRawData:%x\n",pSectionHeader->PointerToRawData);
		printf("PointerToRelocations:%x\n",pSectionHeader->PointerToRelocations);
		printf("PointerToLinenumbers:%x\n",pSectionHeader->PointerToLinenumbers);
		printf("NumberOfRelocations:%x\n",pSectionHeader->NumberOfRelocations);
		printf("NumberOfLinenumbers:%x\n",pSectionHeader->NumberOfLinenumbers);
		printf("Characteristics:%x\n",pSectionHeader->Characteristics);
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + 40);
	}
	fclose(pfile);
	free(pFileBuffer);
    system("pasuse");
	return 0;
	/*
	FILE* file1;
	char* fp;
	file1=fopen("C:\\WINDOWS\\system32\\notepad.exe","rb");
	fseek(file1,0,SEEK_END);
	long size=ftell(file1);
	fseek(file1,0,SEEK_SET);
	fp=(char *)malloc(size);
	if(fp==NULL)
	{
		return 0;
	}
	fread(fp,1,size,file1);
	FILE* file2;
	file2=fopen("C:\\Program Files\\Microsoft Visual Studio\\MyProjects\\test2\\notepad.exe","wb");
	fwrite(fp,1,size,file2);
	free(fp);
	fclose(file2);
	fclose(file1);
	return 0;
	*/
}