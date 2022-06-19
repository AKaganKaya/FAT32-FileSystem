#include "fat32.h"
#include "parser.c"
#include "parser.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

uint32_t FAT_EOC = 0x0FFFFFF8;
uint32_t FAT_FREE_CLUSTER = 0x00000000;
#define MAX_COMMAND_SIZE 255 // The maximum command-line size
#define MAX_FILE_SIZE 16
char formattedDirectory[12];
int32_t current_cluster = 2;
#define ENTRIES_PER_SECTOR 16



void init_environment(struct struct_BPB_struct *bpb, char* file_name, uint32_t *current_cluster)
{
        // char* file_name = "example.img";
        FILE *ptr_file = fopen(file_name, "r");
        fseek(ptr_file, 0, SEEK_SET);
        fread(bpb, sizeof(struct struct_BPB_struct) - sizeof(struct struct_BPBFAT32_struct), 1, ptr_file);
        fseek(ptr_file, sizeof(struct struct_BPB_struct) - sizeof(struct struct_BPBFAT32_struct), SEEK_SET);
        fread(&bpb->extended, sizeof(struct struct_BPBFAT32_struct), 1, ptr_file);
        fclose(ptr_file);
	    *current_cluster = bpb->extended.RootCluster;
}

uint32_t first_sector_of_cluster(struct struct_BPB_struct *bpb, uint32_t cluster_num)
{
	uint32_t first_data_sector = bpb->ReservedSectorCount + (bpb->NumFATs * bpb->extended.FATSize);
    if (cluster_num == 0)
	{
        cluster_num = 2;
    }
	return (((cluster_num-2) * (bpb->SectorsPerCluster) ) + first_data_sector) * bpb->BytesPerSector;
}

void process_filenames(struct struct_FatFileLFN long_file_entry[MAX_FILE_SIZE][MAX_FILE_SIZE], struct struct_FatFile83 file_entry[MAX_FILE_SIZE])
{

    for(int a = 0; a < MAX_FILE_SIZE; a++)
    {
        char* proper_file_name;
        proper_file_name = (char*)malloc(sizeof(char)*255);
        int k = 0;
        if(file_entry[a].attributes == 0 || file_entry[a].filename[0] == 46) 
        {
            continue;
        }
        for(int i = 15; i >= 0; i--)
        {
            if(long_file_entry[a][i].attributes != 15)
            {
                continue;
            }
            else
            {
                for(int j = 0; j < 5; j++)
                {
                    if(long_file_entry[a][i].name1[j] > 41 && long_file_entry[a][i].name1[j] < 176)
                    {
                        proper_file_name[k] = long_file_entry[a][i].name1[j];
                        k++;
                    }
                    else
                    {
                        break;
                    }
                    
                }
                for(int j = 0; j < 6; j++)
                {
                    if(long_file_entry[a][i].name2[j] > 41 && long_file_entry[a][i].name2[j] < 176)
                    {
                        proper_file_name[k] = long_file_entry[a][i].name2[j];
                        k++;
                    }
                    else
                    {
                        break;
                    }
                    
                }
                for(int j = 0; j < 2; j++)
                {
                    if(long_file_entry[a][i].name3[j] > 41 && long_file_entry[a][i].name3[j] < 176)
                    {
                        proper_file_name[k] = long_file_entry[a][i].name3[j];
                        k++;
                    }
                    else
                    {
                        break;
                    }
                    
                }
            }
        }
        printf("%s\t",proper_file_name);
    }
    printf("\n");
}

char** format_directory(char* directory, int* relative_path)
{
    const char delimiter = '/';
    char** arguments = (char**)malloc(sizeof(char*)*255);
    for(int i = 0; i < 255; i++)
    {
        arguments[i] = (char*)malloc(sizeof(char)*255);
    }
    int k = 0;
    int l = 0;
    for(int i = 0; i < 255; i++)
    {
        if(directory[i] == delimiter)
        {
            k++;
            l = 0;
            continue;
        }
        arguments[k][l] = directory[i];
        l++;
    }

    if(arguments[0][0] == '.')
    {
        *relative_path = 1;
    }
    else
    {
        *relative_path = 0;
    }

    return arguments;

}

int find_cluster(char* folder, struct struct_FatFileLFN long_file_entry[MAX_FILE_SIZE][MAX_FILE_SIZE], struct struct_FatFile83 file_entry[MAX_FILE_SIZE])
{
    for(int a = 0; a < MAX_FILE_SIZE; a++)
    {
        char* proper_file_name;
        proper_file_name = (char*)malloc(sizeof(char)*255);
        int k = 0;
        if(file_entry[a].filename[0] == 46) 
        {
            if(file_entry[a].filename[0] == 46 && folder[0] == 46)
            {
                return file_entry->firstCluster;
            }
        }
        for(int i = 15; i >= 0; i--)
        {
            if(long_file_entry[a][i].attributes != 15)
            {
                continue;
            }
            else
            {
                for(int j = 0; j < 5; j++)
                {
                    if(long_file_entry[a][i].name1[j] > 0 && long_file_entry[a][i].name1[j] < 255)
                    {
                        proper_file_name[k] = long_file_entry[a][i].name1[j];
                        k++;
                    }
                    else
                    {
                        break;
                    }
                    
                }
                for(int j = 0; j < 6; j++)
                {
                    if(long_file_entry[a][i].name2[j] > 0 && long_file_entry[a][i].name2[j] < 255)
                    {
                        proper_file_name[k] = long_file_entry[a][i].name2[j];
                        k++;
                    }
                    else
                    {
                        break;
                    }
                    
                }
                for(int j = 0; j < 2; j++)
                {
                    if(long_file_entry[a][i].name3[j] > 0 && long_file_entry[a][i].name3[j] < 255)
                    {
                        proper_file_name[k] = long_file_entry[a][i].name3[j];
                        k++;
                    }
                    else
                    {
                        break;
                    }
                    
                }
            }
        }
        if(strcmp(folder, proper_file_name) == 0)
        {
            return file_entry[a].firstCluster;
        }
    }
    return -1;
}

uint32_t ls(struct struct_BPB_struct *bpb, struct struct_FatFileLFN long_file_entry[MAX_FILE_SIZE][MAX_FILE_SIZE],  struct struct_FatFile83 file_entry[MAX_FILE_SIZE], int cd, int pwd)
{
	uint32_t FirstSectorofCluster = first_sector_of_cluster(bpb, pwd);
	uint32_t counter;
	
	FILE *ptr_img;
	ptr_img = fopen("example.img", "r");

	fseek(ptr_img, FirstSectorofCluster, SEEK_SET);
	for(counter = 0; 2 * counter * sizeof(struct struct_FatFile83) < bpb->SectorsPerCluster * bpb->BytesPerSector; counter ++){
        fread(&long_file_entry[counter][0], sizeof(struct struct_FatFileLFN),1,ptr_img);
        if(long_file_entry[counter][0].sequence_number > 65)
        {
            for(int k = 0; k < long_file_entry[counter][0].sequence_number - 65; k++)
            {
                fread(&long_file_entry[counter][k + 1], sizeof(struct struct_FatFileLFN), 1, ptr_img);
            }
        }
		fread(&file_entry[counter], sizeof(struct struct_FatFile83),1,ptr_img);
	}

    if(cd == 0)
    {
        process_filenames(long_file_entry, file_entry);
    }
	fclose(ptr_img);

	return current_cluster;
}

uint32_t cd(struct struct_BPB_struct *bpb, struct struct_FatFileLFN long_file_entry[MAX_FILE_SIZE][MAX_FILE_SIZE],  struct struct_FatFile83 file_entry[MAX_FILE_SIZE], char* directory)
{
    int relative_path = 0;
    int cluster = -1;
    char** arguments = format_directory(directory, &relative_path);

    if (relative_path == 0)
    {
        ls(bpb, long_file_entry, file_entry, 1, current_cluster);
        for(int i = 1; i < 255; i++)
        {
            if (arguments[i][0] <= 0 || arguments[i][0] > 255)
            {
                break;
            }
            cluster = find_cluster(arguments[i], long_file_entry, file_entry);
            ls(bpb, long_file_entry, file_entry, 1, cluster);
        }
    }
	return cluster;
}

uint32_t root_dir_sector_count(struct struct_BPB_struct* bpb)
{
	return ((bpb->RootEntryCount * 32) + (bpb->TotalSectors32 - 1)) / bpb->TotalSectors32;

}

uint32_t cluster_to_byte_address(struct struct_BPB_struct *bpb, uint32_t cluster_num)
{
	uint32_t this_offset = cluster_num * 4;
	uint32_t this_sector_number = bpb->ReservedSectorCount + (this_offset/bpb->TotalSectors32);
	uint32_t this_ent_offset = this_offset % bpb->TotalSectors32;

	return this_sector_number * bpb->TotalSectors32 + this_ent_offset;
}

/*
	Given offset from the beginning of the file, reads in fat entry. 
*/
uint32_t look_up_fat(struct struct_BPB_struct *bpb, char* fat_image, uint32_t offset)
{
	FILE *ptr_img;
	uint32_t fat_entry;
	ptr_img = fopen(fat_image, "r");
	fseek(ptr_img, offset, SEEK_SET);
	fread(&fat_entry, sizeof(fat_entry),1, ptr_img);
	fclose(ptr_img);
	return (fat_entry);
}

int write_to_FAT(char* fat_image, struct struct_BPB_struct *bpb, uint32_t destinationCluster, uint32_t newFatVal) 
{
    
    FILE* f = fopen(fat_image, "rb+");

    fseek(f, cluster_to_byte_address(bpb, destinationCluster), 0);
    fwrite(&newFatVal, 4, 1, f);
    fclose(f);
    return 0;
}
int createEntry(struct struct_FatFile83 * entry,
			const char * direction_name, 
			const char * ext,
			int isDir,
			uint32_t firstCluster,
			uint32_t filesize) 
{
	
    //set the same no matter the entry
    entry->reserved = 0; 
	entry->creationTimeMs = 0;

	entry->creationTime = 0;
	entry->creationDate = 0;

	entry->lastAccessTime = 0;
	entry->modifiedTime = 0;
	entry->modifiedDate = 0;
	strcpy(entry->filename, direction_name);
    //check for file extention
    if (ext)
    {
    	strcat(entry->filename, " ");
    	strcat(entry->filename, ext);
    }
    

    //  decompose address
    entry->firstCluster = firstCluster;
	entry->eaIndex = firstCluster >> 16;  
	// entry->FstClusLO = current_cluster/0x100;
	// entry->FstClusHI = current_cluster % 0x100;

	//  check if directory and set attributes
    if(isDir == 1) {
        entry->fileSize = 0;
        entry->attributes = 32;
	} else {
        entry->fileSize = filesize;
        entry->attributes = 64;
	}
    return 0; 
}

int count_clusters(struct struct_BPB_struct *bpb) 
{
	int FATSz;
	int TotSec;
	int sectors_per_region;
	FATSz = bpb->extended.FATSize;

	TotSec = bpb->TotalSectors32;
    
	sectors_per_region = TotSec - (bpb->ReservedSectorCount + (bpb->NumFATs * FATSz) + root_dir_sector_count(bpb));
	// sectors_per_cluster
	return sectors_per_region / bpb->SectorsPerCluster;
}

uint32_t FAT_find_free_cluster(char* fat_image, struct struct_BPB_struct *bpb) 
{
    uint32_t free_cluster_index = 0;
    int found = 0;
    uint32_t totalClusters = (uint32_t) count_clusters(bpb);
    while(free_cluster_index < totalClusters) 
    {
        uint32_t fat_entry;
        FILE* ptr_img = fopen(fat_image, "r");
        fseek(ptr_img, cluster_to_byte_address(bpb, free_cluster_index), SEEK_SET);
        fread(&fat_entry, sizeof(fat_entry),1, ptr_img);
        if ((fat_entry == FAT_FREE_CLUSTER)){
            found =1;
            break;
        }
        free_cluster_index++;
    }
    if (found == 1)
    	return free_cluster_index;
    else
    	return 0;  // FAT is FULL
}
FatFile83 * readEntry(char* fat_image, struct struct_BPB_struct *bpb, FatFile83 * entry, uint32_t clusterNum, int offset)
{
    offset *= 32;
    uint32_t dataAddress = first_sector_of_cluster(bpb, clusterNum);
    
    FILE* f = fopen(fat_image, "r");
    fseek(f, dataAddress + offset, 0);
	fread(entry, sizeof(FatFile83), 1, f);
    
    fclose(f);
    return entry;
}

uint32_t byteOffsetofDirectoryEntry(struct struct_BPB_struct *bpb, uint32_t clusterNum, int offset) {
    offset *= 32;
    uint32_t dataAddress = first_sector_of_cluster(bpb, clusterNum);
    return (dataAddress + offset);
}


uint32_t dataSector_NextOpen(char* fat_image, struct struct_BPB_struct *bpb, uint32_t pwdCluster) 
{
	struct struct_FatFile83 dir;

    //printf("dir Size: %d\n", dirSizeInCluster);
    uint32_t clusterCount;
    char fileName[12];
    uint32_t offset = 0;
    uint32_t increment = 2;
    //each dir is a cluster
    for(clusterCount = 0; clusterCount * sizeof(struct struct_FatFile83) < bpb->TotalSectors32; clusterCount++) 
    {
        for(; offset < ENTRIES_PER_SECTOR; offset += increment) 
        {
            
            readEntry(fat_image, bpb, &dir, pwdCluster, offset);
            //printf("\ncluster num: %d\n", pwdCluster);
            //makeFileDecriptor(&dir, &fd);

            if( dir.filename[0] == 0x00 || dir.filename[0] == 0xE5 /*isEntryEmpty(&fd) == TRUE */) {
                //this should tell me exactly where to write my new entry to
                //printf("cluster #%d, byte offset: %d: ", offset, byteOffsetofDirectoryEntry(bs, pwdCluster, offset));             
                return byteOffsetofDirectoryEntry(bpb, pwdCluster, offset);
            }
        }
        //pwdCluster becomes the next cluster in the chain starting at the passed in pwdCluster
       pwdCluster = look_up_fat(bpb, fat_image, cluster_to_byte_address(bpb, pwdCluster)); 
      
    }
    return -1; //cluster chain is full
}

uint32_t FAT_extendClusterChain(char* fat_image, struct struct_BPB_struct *bpb,  uint32_t pwd_cluster) 
{
    uint32_t temp_cluster = pwd_cluster;
	uint32_t fat_entry = look_up_fat(bpb, fat_image, cluster_to_byte_address(bpb, temp_cluster));
	
	while (fat_entry != 0x0FFFFFF8 && fat_entry != 0x0FFFFFFF)
	{
		temp_cluster = fat_entry;
		fat_entry = look_up_fat(bpb, fat_image, cluster_to_byte_address(bpb, temp_cluster));
	}
	uint32_t firstFreeCluster = FAT_find_free_cluster(fat_image, bpb);
	
    write_to_FAT(fat_image,bpb, firstFreeCluster, FAT_EOC);
    write_to_FAT(fat_image, bpb, temp_cluster, firstFreeCluster);
    return firstFreeCluster;
}

int writeFileEntry(char* fat_image, struct struct_BPB_struct *bpb, struct struct_FatFile83 * entry, uint32_t destinationCluster, int isDotEntries) 
{
    int dataAddress;
    int freshCluster;
    FILE* f = fopen(fat_image, "rb+");
    
    if(isDotEntries == 0) 
    {
        if((dataAddress = dataSector_NextOpen(fat_image,bpb, destinationCluster)) != -1) {//-1 means current cluster is at capacity
            fseek(f, dataAddress, 0);
            fwrite (entry , 1 , sizeof(struct struct_FatFile83) , f );
        } else {
            freshCluster = FAT_extendClusterChain(fat_image,bpb, destinationCluster);
            dataAddress = dataSector_NextOpen(fat_image,bpb, freshCluster);
			//  decompose address
	        fseek(f, dataAddress, 0);
            fwrite (entry , 1 , sizeof(struct struct_FatFile83) , f );
        }
    } else {
        struct struct_FatFile83 dotEntry;
        struct struct_FatFile83 dotDotEntry;

        //makeSpecialDirEntries(&dotEntry, &dotDotEntry, destinationCluster, environment.pwd_cluster);
        createEntry(&dotEntry, ".", "", 1, destinationCluster, 0);	
		createEntry(&dotDotEntry, "..", "", 1, current_cluster, 0);	

        //seek to first spot in new dir cluster chin and write the '.' entry
        dataAddress = byteOffsetofDirectoryEntry(bpb, destinationCluster, 0);
        fseek(f, dataAddress, 0);
        fwrite (&dotEntry , 1 , sizeof(struct struct_FatFile83) , f );
        //seek to second spot in new dir cluster chin and write the '..' entry
        dataAddress = byteOffsetofDirectoryEntry(bpb, destinationCluster, 1);
        fseek(f, dataAddress, 0);
        fwrite (&dotDotEntry , 1 , sizeof(struct struct_FatFile83) , f );
    }
     fclose(f);
     return 0;
}


uint32_t mkdir(char* fat_image, struct struct_BPB_struct *bpb, const char * dirName, const char * extention, uint32_t targetDirectoryCluster)
{
    // struct DIR_ENTRY newDirEntry;
    struct struct_FatFile83 newDirEntry;
    //write directory entry to pwd
    uint32_t beginNewDirClusterChain = FAT_find_free_cluster(fat_image, bpb); // free cluster
    write_to_FAT(fat_image, bpb, beginNewDirClusterChain, FAT_EOC); //mark that its End of Cluster

    createEntry(&newDirEntry, dirName, extention, 1, beginNewDirClusterChain, 0);

    writeFileEntry(fat_image, bpb, &newDirEntry, targetDirectoryCluster, 0);
    
    //writing dot entries to newly allocated cluster chain
    writeFileEntry(fat_image, bpb, &newDirEntry, beginNewDirClusterChain, 1);

   return 0;
}

int main()
{
    char *cmd_str = (char *)malloc(MAX_COMMAND_SIZE);
    struct struct_BPBFAT32_struct BPBFAT32_struct;
    struct struct_BPB_struct BPB_struct;

    struct struct_FatFile83 file_struct[MAX_FILE_SIZE];
    struct struct_FatFileLFN long_file_struct[MAX_FILE_SIZE][MAX_FILE_SIZE];
    init_environment(&BPB_struct, "example.img", &current_cluster);
    while(1)
    {
        int32_t root_address;
        struct parsed_input parsed;
        printf(">");
        while (!fgets(cmd_str, MAX_COMMAND_SIZE, stdin));
        if(strcmp(cmd_str, "quit") == 0)
        {
            break;
        }
        parse(&parsed, cmd_str);

        if (parsed.type == LS)
        {
            int temp_cluster;
            temp_cluster = cd(&BPB_struct, long_file_struct, file_struct, parsed.arg1);
            ls(&BPB_struct, long_file_struct, file_struct, 0, temp_cluster);
            ls(&BPB_struct, long_file_struct, file_struct, 1, current_cluster);
        }

        else if (parsed.type == CD)
        {
            current_cluster = cd(&BPB_struct, long_file_struct, file_struct, parsed.arg1);
        }

        else if(parsed.type == MKDIR)
        {
            mkdir("example.img", &BPB_struct, parsed.arg1, NULL, current_cluster);
        }
    }
    return 0;
}