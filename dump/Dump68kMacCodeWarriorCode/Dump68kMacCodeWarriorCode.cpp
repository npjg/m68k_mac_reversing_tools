// Based on the following original source code:
/* Project...: C++ and ANSI-C Compiler Environment			*/
/* Name......: Startup.c						*/
/* Purpose...: 68K application startup code example			*/
/* Copyright.: Copyright � 1993-1997 Metrowerks, Inc.			*/

#include <iostream>
#include <filesystem>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace fs = std::filesystem;

// Forward declare the core C logic functions.
extern "C" {
    void* __Startup__(char *data0_resource, char *code1_resource, unsigned long code1_size, unsigned long above_a5_size, unsigned long below_a5_size);
    static char *__relocate__(char *xref, char *segm, unsigned long a5_base, unsigned long code1_base);
    static char *__decomp_data__(char *ptr,char *datasegment);
}

const long code_resource_offset = 0x60000;

// Helper functions to read and write big-endian integers
static inline unsigned long read_be32(const char* ptr) {
	return ((unsigned char)ptr[0] << 24) |
	       ((unsigned char)ptr[1] << 16) |
	       ((unsigned char)ptr[2] << 8) |
	       ((unsigned char)ptr[3]);
}

static inline unsigned short read_be16(const char* ptr) {
	return ((unsigned char)ptr[0] << 8) |
	       ((unsigned char)ptr[1]);
}

static inline void write_be32(char* ptr, unsigned long value) {
	ptr[0] = (value >> 24) & 0xFF;
	ptr[1] = (value >> 16) & 0xFF;
	ptr[2] = (value >> 8) & 0xFF;
	ptr[3] = value & 0xFF;
}

// C++ functionality to help with directory scanning of the resource_dasm resource export. Really, we should just parse
// the MacBinary files directly, but this provides a bit more flexibility until we are ready for that.
struct ResourceFiles {
    std::string code0_path;
    std::string data0_path;
    std::string code1_path;
    std::string basename;
};
int dump(const ResourceFiles& resources, const std::string& dump_filename);
bool find_resource_files(const std::string& directory_path, ResourceFiles& resources);

int main(int argc, char* argv[]) {
    // Parse command line arguments.
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <resources_directory> [output_dump_file]" << std::endl;
        std::cout << "  Dumps a 68k Mac application compiled with CodeWarrior for importing into Ghidra." << std::endl;
        std::cout << "  Handles the custom CodeWarrior A5 world/relocation information encoding." << std::endl;
        std::cout << std::endl;
        std::cout << "  The directory must contain exactly one of each:" << std::endl;
        std::cout << "    *_CODE_0.bin" << std::endl;
        std::cout << "    *_DATA_0.bin" << std::endl;
        std::cout << "    *_CODE_1.bin" << std::endl;
        return 1;
    }

    std::string directory_path = argv[1];
    std::string dump_filename = "dump.bin";
    if (argc > 2) {
        dump_filename = argv[2];
    }

    // Find resource files in directory.
    ResourceFiles resources;
    if (!find_resource_files(directory_path, resources)) {
        return 1;
    }

    // Use basename for output file if not specified.
    if (argc <= 2) {
        dump_filename = resources.basename + "_dump.bin";
    }

    // Execute dump logic.
    return dump(resources, dump_filename);
}

bool find_resource_files(const std::string& directory_path, ResourceFiles& resources) {
    // Verify directory exists
    if (!fs::exists(directory_path) || !fs::is_directory(directory_path)) {
        std::cerr << "ERROR: Directory does not exist: " << directory_path << std::endl;
        return false;
    }

    std::vector<std::string> code0_candidates;
    std::vector<std::string> data0_candidates;
    std::vector<std::string> code1_candidates;

    // Find all matching BIN files from the export.
    for (const auto& entry : fs::directory_iterator(directory_path)) {
        if (!entry.is_regular_file()) {
            continue;
        }

        std::string filename = entry.path().filename().string();
        std::string extension = entry.path().extension().string();

        // VALIDATE: Extension must be .bin
        if (extension != ".bin") {
            continue;
        }

        // CATEGORIZE: Based on resource type in filename
        if (filename.find("_CODE_0") != std::string::npos) {
            code0_candidates.push_back(entry.path().string());
        } else if (filename.find("_DATA_0") != std::string::npos) {
            data0_candidates.push_back(entry.path().string());
        } else if (filename.find("_CODE_1") != std::string::npos) {
            code1_candidates.push_back(entry.path().string());
        }
    }

    // Validate that exactly one of each resource type exists
    bool all_resources_found =
        code0_candidates.size() == 1 &&
        data0_candidates.size() == 1 &&
        code1_candidates.size() == 1;

    if (!all_resources_found) {
        std::cerr << "ERROR: Could not find exactly one of each required resource file" << std::endl;
        std::cerr << "  Found " << code0_candidates.size() << " *_CODE_0.bin file(s)" << std::endl;
        std::cerr << "  Found " << data0_candidates.size() << " *_DATA_0.bin file(s)" << std::endl;
        std::cerr << "  Found " << code1_candidates.size() << " *_CODE_1.bin file(s)" << std::endl;
        std::cerr << "Required: Exactly one of each file matching patterns:" << std::endl;
        std::cerr << "  *_CODE_0.bin" << std::endl;
        std::cerr << "  *_DATA_0.bin" << std::endl;
        std::cerr << "  *_CODE_1.bin" << std::endl;
        return false;
    }

    // Extract basename from CODE_0 filename.
    std::string code0_filename = fs::path(code0_candidates[0]).filename().string();
    size_t suffix_pos = code0_filename.find("_CODE_0.bin");
    resources.basename = code0_filename.substr(0, suffix_pos);

    resources.code0_path = code0_candidates[0];
    resources.data0_path = data0_candidates[0];
    resources.code1_path = code1_candidates[0];

    std::cout << "Found resource files with basename: " << resources.basename << std::endl;
    std::cout << "  CODE_0: " << resources.code0_path << std::endl;
    std::cout << "  DATA_0: " << resources.data0_path << std::endl;
    std::cout << "  CODE_1: " << resources.code1_path << std::endl;

    return true;
}

// Execute the dump logic with discovered resource files
int dump(const ResourceFiles& resources, const std::string& dump_filename) {
    // EXTRACT: Convert C++ strings to C strings before entering goto section
    const char* code0_file = resources.code0_path.c_str();
    const char* data0_file = resources.data0_path.c_str();
    const char* code1_file = resources.code1_path.c_str();
    const char* dump_file_cstr = dump_filename.c_str();

    char* data0_resource = NULL;
    char* code0_resource = NULL;
    char* code1_resource = NULL;
    void* a5_world_base = NULL;
    FILE* file = NULL;
    unsigned long file_size;
    unsigned long code1_size = 0;
    unsigned long above_a5_size = 0;
    unsigned long below_a5_size = 0;

    // Load CODE 0 resource (jumptable)
    if (code0_file != NULL) {
        file = fopen(code0_file, "rb");
        if (file == NULL) {
            printf("ERROR: Cannot open CODE 0 resource file: %s\n", code0_file);
            goto cleanup;
        }

        // Get file size
        fseek(file, 0, SEEK_END);
        file_size = ftell(file);
        fseek(file, 0, SEEK_SET);
        if (file_size < 16) {
            printf("ERROR: CODE 0 resource file too small (need at least 16 bytes)\n");
            fclose(file);
            goto cleanup;
        }

        // Allocate buffer and read file
        code0_resource = (char*)malloc(file_size);
        if (code0_resource == NULL) {
            printf("ERROR: Cannot allocate memory for CODE 0 resource (%ld bytes)\n", file_size);
            goto cleanup;
        }

        if (fread(code0_resource, 1, file_size, file) != file_size) {
            printf("ERROR: Failed to read CODE 0 resource file\n");
            goto cleanup;
        }

        fclose(file);
        file = NULL;

        // Parse jumptable header (big-endian)
        above_a5_size = read_be32(code0_resource);
        code0_resource += 4;
        below_a5_size = read_be32(code0_resource);
        code0_resource += 4;
        unsigned long jump_table_size = read_be32(code0_resource);
        code0_resource += 4;
        unsigned long jump_table_offset = read_be32(code0_resource);
        code0_resource += 4;

        printf("Jumptable info:\n");
        printf("  Above A5 size: 0x%lx (%ld bytes)\n", above_a5_size, above_a5_size);
        printf("  Below A5 size: 0x%lx (%ld bytes)\n", below_a5_size, below_a5_size);
        printf("  Jump table size: 0x%lx (%ld bytes)\n", jump_table_size, jump_table_size);
        printf("  Jump table offset: 0x%lx\n", jump_table_offset);
    }

    // Load DATA 0 resource
    if (data0_file != NULL) {
        file = fopen(data0_file, "rb");
        if (file == NULL) {
            printf("ERROR: Cannot open DATA 0 resource file: %s\n", data0_file);
            goto cleanup;
        }

        // Get file size
        fseek(file, 0, SEEK_END);
        file_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        // Allocate buffer and read file
        data0_resource = (char*)malloc(file_size);
        if (data0_resource == NULL) {
            printf("ERROR: Cannot allocate memory for DATA 0 resource (%ld bytes)\n", file_size);
            goto cleanup;
        }

        if (fread(data0_resource, 1, file_size, file) != file_size) {
            printf("ERROR: Failed to read DATA 0 resource file\n");
            goto cleanup;
        }

        fclose(file);
        file = NULL;
    }

    // Load CODE 1 resource
    if (code1_file != NULL) {
        file = fopen(code1_file, "rb");
        if (file == NULL) {
            printf("ERROR: Cannot open CODE 1 resource file: %s\n", code1_file);
            goto cleanup;
        }

        // Get file size
        fseek(file, 0, SEEK_END);
        file_size = ftell(file);
        fseek(file, 0, SEEK_SET);
        if (file_size <= 0) {
            printf("ERROR: Invalid CODE 1 resource file size: %ld\n", file_size);
            goto cleanup;
        }

        code1_size = file_size; // Store the size for later use

        // Allocate buffer and read file
        code1_resource = (char*)malloc(file_size);
        if (code1_resource == NULL) {
            printf("ERROR: Cannot allocate memory for CODE 1 resource (%ld bytes)\n", file_size);
            goto cleanup;
        }

        if (fread(code1_resource, 1, file_size, file) != file_size) {
            printf("ERROR: Failed to read CODE 1 resource file\n");
            goto cleanup;
        }

        fclose(file);
        file = NULL;
    }

    // Call the startup function with the loaded resources
    a5_world_base = __Startup__(data0_resource, code1_resource, code1_size, above_a5_size, below_a5_size);
    if (a5_world_base != NULL) {
        FILE* dump_output = fopen(dump_file_cstr, "wb");
        if (dump_output == NULL) {
            printf("ERROR: Cannot create dump file: %s\n", dump_file_cstr);
            goto cleanup;
        }

        // Calculate total dump size (A5 world + CODE resource at 0x10000)
        const long total_a5_world_size = below_a5_size + above_a5_size;
        const long total_dump_size = code_resource_offset + code1_size;

        // Write the entire dump to file
        size_t written = fwrite(a5_world_base, 1, total_dump_size, dump_output);
        fclose(dump_output);

        if (written == total_dump_size) {
            printf("Memory dump created successfully: %ld bytes written to %s\n", (long)written, dump_file_cstr);
            printf("A5 offset within dump: 0x%lx (decimal: %ld)\n", below_a5_size, below_a5_size);
            printf("CODE resource offset within dump: 0x%lx (decimal: %ld)\n", code_resource_offset, code_resource_offset);
            printf("A5 world size: 0x%lx bytes\n", total_a5_world_size);
            printf("CODE resource size: 0x%lx bytes\n", code1_size);
        } else {
            printf("ERROR: Incomplete memory dump - only %ld of %ld bytes written\n",
                   (long)written, total_dump_size);
            goto cleanup;
        }
    } else {
        printf("ERROR: A5 world setup failed\n");
        goto cleanup;
    }

    if (code0_resource) free(code0_resource);
    if (data0_resource) free(data0_resource);
    if (code1_resource) free(code1_resource);
    if (a5_world_base) free(a5_world_base);

    return 0;

cleanup:
    // Clean up file handle if still open
    if (file != NULL) {
        fclose(file);
    }

    // Clean up allocated resources
    if (code0_resource) free(code0_resource);
    if (data0_resource) free(data0_resource);
    if (code1_resource) free(code1_resource);
    if (a5_world_base) free(a5_world_base);

    return 1;
}

/****************************************************************/
/* Purpose..: The Startup routine for Applications		*/
/* Input....: ---						*/
/* Returns..: ---						*/
/****************************************************************/
void* __Startup__(char *data0_resource, char *code1_resource, unsigned long code1_size, unsigned long above_a5_size, unsigned long below_a5_size)
{
	// Allocate memory for the entire dump (A5 world + CODE resource at 0x10000).
    const long total_a5_world_size = below_a5_size + above_a5_size;
    const long total_dump_size = code_resource_offset + code1_size;
    char* dump_base = (char*)malloc(total_dump_size);
    if (dump_base == NULL) {
        return NULL;
    }
    memset(dump_base, 0, total_dump_size);

    // Calculate A5 position within the allocated memory.
    char* a5_ptr = dump_base + below_a5_size;
    char* code_ptr = dump_base + code_resource_offset;
	long a5_unrelocated = below_a5_size;
	long code1_unrelocated = code_resource_offset;

    // Set up pointers for different regions.
    //char* data_area_below = a5_world_base;   // Below A5.
    //char* data_area_above = a5_ptr + 32 + 8; // Above A5 (skip header).
    //char* data_area_above_end = a5_ptr + data_bytes_above_a5;

    // Initialize global data area from DATA 0 resource
    if (data0_resource != NULL) {
        char* data0_ptr = (char*)data0_resource;

        // DATA 0 resource layout:
        // +---------------------------------+
        // | long:   offset of CODE 1 xrefs  |---+
        // +---------------------------------+   |
        // | char[]: compressed init data    |   |
        // +---------------------------------+   |
        // | char[]: compressed DATA 0 xrefs |   |
        // +---------------------------------+   |
        // | char[]: compressed CODE 1 xrefs |<--+
        // +---------------------------------+

        // Decompress initialization data into A5 world
        char* init_data_ptr = data0_ptr + 4;  // Skip CODE 1 xrefs offset.
        char* xref_data_ptr = __decomp_data__(init_data_ptr, a5_ptr);

        // Store the base address of CODE segment 1 in the A5 world
        // Export 0 [A5 + 0x22]: CODE 1 offset 0x0 after header
        // a5_ptr[0x22] = code1_resource;

        // Copy CODE resource to its position in the dump
        if (code1_resource != NULL) {
            memcpy(code_ptr, code1_resource, code1_size);
        }

        // Relocate the data segment (A5 world)
		// TODO: Is this wrong? Do we need to set the relocations to read AFTER this one?
        xref_data_ptr = __relocate__(xref_data_ptr, a5_ptr, a5_unrelocated, code1_unrelocated);

        // Relocate CODE segment 1 (now in the dump at 0x60000)
        xref_data_ptr = __relocate__(xref_data_ptr, code_ptr, a5_unrelocated, code1_unrelocated);

        printf("Dump allocated at: %p\n", dump_base);
        printf("A5 pointer at: %p (offset 0x%lx)\n", a5_ptr, below_a5_size);
        printf("CODE pointer at: %p (offset 0x%lx)\n", code_ptr, code_resource_offset);
        printf("Below A5 size: 0x%lx bytes\n", below_a5_size);
        printf("Above A5 size: 0x%lx bytes\n", above_a5_size);
        printf("Total A5 world size: 0x%lx bytes\n", total_a5_world_size);
        printf("CODE resource size: 0x%lx bytes\n", code1_size);
        printf("Total dump size: 0x%lx bytes\n", total_dump_size);
    }

    // Return the base of the allocated dump for writing
    return dump_base;
}


/****************************************************************/
/* Purpose..: Decompress the DATA resource			*/
/* Input....: pointer to DATA resource data			*/
/* Input....: pointer to A5 resource				*/
/* Returns..: pointer to data after init data			*/
/****************************************************************/

//
//	Pack Patterns:
//
//	0x1xxx xxxx: <raw data>		x+1 (1..128)	raw data bytes
//	0x01xx xxxx:			x+1 (1..64)		<x> 0x00 data bytes
//	0x001x xxxx: yyyy yyyy		x+2 (2..33)		<x> <y> data bytes
//	0x0001 xxxx:			x+1 (1..16)		<x> 0xFF data bytes
//	0x0000 0001:			pattern: 0x00000000FFFFXXXX
//	0x0000 0010:			pattern: 0x00000000FFXXXXXX
//	0x0000 0011:			pattern: 0xA9F00000XXXX00XX
//	0x0000 0100:			pattern: 0xA9F000XXXXXX00XX
//	0x0000 0000:	end of data
//

static char *__decomp_data__(char *ptr,char *datasegment)
{
	int	i,data;
	char	*to,c;

	for(i=0; i<3; i++)
	{
		long offset = read_be32(ptr);
		ptr += 4;
		to=datasegment+offset;
		while(1)
		{
			data=*ptr++;
			if(data&0x80)
			{	//	decompress (x&0x7f)+1 raw data bytes
				data&=0x7F; do *to++=*ptr++; while(--data>=0); continue;
			}
			if(data&0x40)
			{	//	decompress (x&0x3f)+1 0x00 data bytes
//				data&=0x3F; c=0x00; goto cloop;
				to+=(data&0x3F)+1; continue;	//	data is already initilized to 0x00
			}
			if(data&0x20)
			{	//	decompress (x&0x1f)+2 repeating data bytes
				data=(data&0x1F)+1; c=*ptr++; goto cloop;
			}
			if(data&0x10)
			{	//	decompress (x&0x0f)+1 0xFF data bytes
				data&=0x0F; c=0xFF;
			cloop:	do *to++=c; while(--data>=0); continue;
			}
			switch(data)
			{
			case 0x00: break;
//			case 0x01: *to++=0x00; *to++=0x00; *to++=0x00; *to++=0x00; *to++=0xFF; *to++=0xFF; *to++=*ptr++; *to++=*ptr++; continue;
//			case 0x02: *to++=0x00; *to++=0x00; *to++=0x00; *to++=0x00; *to++=0xFF; *to++=*ptr++; *to++=*ptr++; *to++=*ptr++; continue;
//			case 0x03: *to++=0xA9; *to++=0xF0; *to++=0x00; *to++=0x00; *to++=*ptr++; *to++=*ptr++; *to++=0x00; *to++=*ptr++; continue;
//			case 0x04: *to++=0xA9; *to++=0xF0; *to++=0x00; *to++=*ptr++; *to++=*ptr++; *to++=*ptr++; *to++=0x00; *to++=*ptr++; continue;
			case 0x01: to+=4; *to++=0xFF; *to++=0xFF; *to++=*ptr++; *to++=*ptr++; continue;
			case 0x02: to+=4; *to++=0xFF; *to++=*ptr++; *to++=*ptr++; *to++=*ptr++; continue;
			case 0x03: *to++=0xA9; *to++=0xF0; to+=2; *to++=*ptr++; *to++=*ptr++; to++; *to++=*ptr++; continue;
			case 0x04: *to++=0xA9; *to++=0xF0; to++; *to++=*ptr++; *to++=*ptr++; *to++=*ptr++; to++; *to++=*ptr++; continue;
			default: exit(15);
			}
			break;
		}
	}
	return ptr;
}

/****************************************************************/
/* Purpose..: Relocate code/data references of a segment	*/
/* Input....: pointer to relocation data			*/
/* Input....: pointer to segments base address			*/
/* Input....: pointer to reloaction base address		*/
/* Returns..: pointer to end of relocation data			*/
/****************************************************************/
static char *__reloc_compr__(char *ptr,char *segment,unsigned long relocbase, unsigned long a5_base)
{
	long	offset;
	unsigned long relocations;
	char	c;

	relocations = read_be32(ptr);
	ptr += 4;

	printf("Relocating %ld references (base 0x%lx)\n", relocations, relocbase);
	for(offset=0L; relocations>0; relocations--)
	{
		c=*ptr++;
		if(c&0x80)
		{	//	8-bit signed delta
			c<<=1; offset+=c;
		}
		else
		{
			if(c&0x40)
			{	//	15-bit unsigned delta
				short word_val = read_be16(ptr - 1);  // c is first byte, read second byte
				ptr++;
				offset+=(short)(word_val<<2)>>1;
			}
			else
			{	//	direct signed 31-bit offset
				long lword_val = read_be32(ptr - 1);  // c is first byte, read remaining 3 bytes
				ptr += 3;
				offset=(lword_val<<2)>>1;
			}
		}

		// Get the current value before relocation (big-endian)
		char *position = segment + offset;
		unsigned long unrelocated_value = read_be32(position);

		// Perform the relocation and write back in big-endian format
		unsigned long relocated_value = unrelocated_value + relocbase;
		write_be32(position, relocated_value);

		// Log the relocation details
		printf("  Offset 0x%lX + 0x%lX = 0x%lX: 0x%lX + 0x%lX = 0x%lX\n",
			offset,
			a5_base,
			offset + a5_base,
			unrelocated_value,
			relocbase,
			relocated_value);
	}
	return ptr;
}

/****************************************************************/
/* Purpose..: Relocate code/data references of segment		*/
/* Input....: xref: pointer to xref data			*/
/* Input....: segm: pointer to current segment			*/
/* Input....: a5_base: base address for A5 world (DATA segment) */
/* Input....: code1_base: base address of CODE segment 1	*/
/* Returns..: pointer to data after xref			*/
/****************************************************************/
static char *__relocate__(char *xref, char *segm, unsigned long a5_base, unsigned long code1_base)
{
	char *ptr = xref;

	// Relocate references to DATA segment (A5).
	printf("*** RELOCATE DATA 0 ***\n");
	ptr = __reloc_compr__(ptr, segm, a5_base, a5_base);

	// Relocate references to CODE segment 1.
	printf("*** RELOCATE CODE 1 ***\n");
	ptr = __reloc_compr__(ptr, segm, code1_base, a5_base);

	// Relocate references to same CODE segment.
	// TODO: Understand what this actually is.
	printf("RELOCATE REFERENCES TO SAME CODE SEGMENT ***");
	ptr = __reloc_compr__(ptr, segm, (long)segm, a5_base);

	return ptr;
}
