// Creates a Ghidra-loadable binary image of a CodeWarrior 68k classic Mac OS program.
// Based on 68k assembly from CodeWarrior Pro 1 (MacOS Support:Libraries:Runtime:Runtime 68K:(Sources):Appl68KStartup.c):
/* Project...: C++ and ANSI-C Compiler Environment			*/
/* Name......: Startup.c						*/
/* Purpose...: 68K application startup code example			*/
/* Copyright.: Copyright � 1993-1997 Metrowerks, Inc.			*/

#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

namespace fs = std::filesystem;

// From CodeWarrior's StartupLib.h.
struct SegmentHeader {
    int16_t   jtsoffset;      // A5 relative offset of this segment's jump table (short version)
    int16_t   jtentries;      // number of entries in this segment's jump table
    int32_t   jtloffset;      // A5 relative offset of this segment's jump table (long version)
    int32_t   xrefoffset;     // offset of xref data in this CODE resource
    // char code[];         // the code follows
} __attribute__((packed));

// From CodeWarrior's StartupLib.h.
// This is DIFFERENT from the default Mac jump table entry. The default one would be this:
// struct AppleJumpTableEntry {
//     uint16 offset;           // +0: offset from beginning of segment
//     uint16 moveOpcode;       // +2: 0x3F3C (MOVE.W #immediate,-(SP))
//     uint16 segment;          // +4: segment number (immediate operand)
//     uint16 loadSegTrap;      // +6: Instruction (absolute jump for loaded entry; _LoadSeg for unloaded entry)
// };
// CodeWarrior uses its own _LoadSeg to handle this custom format (as well as relocations).
struct JumpTableEntry {
    // Instruction (absolute jump for loaded entry; _LoadSeg for unloaded entry).
    uint16_t jumpinstruction;
    // Absolute or relative address of routine (immediate; no stack push).
    int32_t jumpaddress;
    // Routine's segment number.
    uint16_t segment;
} __attribute__((packed));

struct CodeSegment {
    int segment_number;
    std::string path;
    uint32_t size;
};

// C logic functions from original assembly.
extern "C" {
    void *__Startup__(char *data0_resource, std::vector<CodeSegment>& code_segments, uint32_t above_a5_size, uint32_t below_a5_size, char* segment_buffers[]);
    static int __LoadSeg__(int16_t segment_number, char *code_resource, uint32_t code_size, uint32_t a5_base, uint32_t code_base, char *code_dest, char *dump_base);
    static char *__relocate__(char *xref, char *segm, uint32_t a5_base, uint32_t code1_base);
    static char *__decomp_data__(char *ptr,char *datasegment);
}

const uint32_t code_resource_offset = 0x60000;

// Helper functions to read and write big-endian integers.
static inline uint32_t read_be32(const char* ptr) {
	return ((unsigned char)ptr[0] << 24) |
	       ((unsigned char)ptr[1] << 16) |
	       ((unsigned char)ptr[2] << 8) |
	       ((unsigned char)ptr[3]);
}

static inline uint16_t read_be16(const char* ptr) {
	return ((unsigned char)ptr[0] << 8) |
	       ((unsigned char)ptr[1]);
}

static inline void write_be32(char* ptr, uint32_t value) {
	ptr[0] = (value >> 24) & 0xFF;
	ptr[1] = (value >> 16) & 0xFF;
	ptr[2] = (value >> 8) & 0xFF;
	ptr[3] = value & 0xFF;
}

static inline void write_be16(char* ptr, uint16_t value) {
	ptr[0] = (value >> 8) & 0xFF;
	ptr[1] = value & 0xFF;
}

//region C++ File I/O Wrappers
// C++ functionality to help with reading from the resource_dasm resource export directory. This directory looks like this:
//  - Yukon Trail_CODE_0.bin
//  - Yukon Trail_CODE_1_Info.bin
//    [more CODE resources...]
//  - Yukon Trail_DATA_0.bin
//    [more resource types...]
// TODO: Support reading MacBinary archives directly so we don't have to export with resource_dasm first. However, referencing
// the resource_dasm disassembly is very helpful for reversing anyway, so I'm inclined to leave this as is.
struct ResourceFiles {
    std::string code0_path;
    std::string data0_path;
    std::vector<CodeSegment> code_segments;  // All CODE segments after CODE 0
    std::string basename;
};
int dump(const ResourceFiles& resources, const std::string& dump_filename);
bool find_resource_files(const std::string& directory_path, ResourceFiles& resources);

int main(int argc, char* argv[]) {
    // Check command line arguments.
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <resource_dasm_export_directory> [output_dump_file]" << std::endl;
        std::cout << "  Dumps a 68k Mac application compiled with CodeWarrior to a flat image for Ghidra." << std::endl;
        std::cout << "  Handles the custom CodeWarrior A5 world/relocation information encoding and jumptable loading." << std::endl;
        return 1;
    }

    // Find resource files in the resource_dasm export directory.
    std::string directory_path = argv[1];
    ResourceFiles resources;
    if (!find_resource_files(directory_path, resources)) {
        return 1;
    }

    // Use the original executable's name in the output filename.
    std::string dump_filename;
    if (argc > 2) {
        dump_filename = argv[2];
    } else {
        dump_filename = resources.basename + "_dump.bin";
    }

    // Execute the dump.
    return dump(resources, dump_filename);
}

bool find_resource_files(const std::string& directory_path, ResourceFiles& resources) {
    // Verify directory exists.
    if (!fs::exists(directory_path) || !fs::is_directory(directory_path)) {
        std::cerr << "ERROR: Directory does not exist: " << directory_path << std::endl;
        return false;
    }

    std::vector<std::string> code0_candidates;
    std::vector<std::string> data0_candidates;
    // Map the segment number to the path. In the resource_dasm export, each segment has its own file.
    std::map<int, std::string> code_segment_map;

    // Find all matching BIN files from the export.
    for (const auto& entry : fs::directory_iterator(directory_path)) {
        if (!entry.is_regular_file()) {
            continue;
        }

        std::string filename = entry.path().filename().string();
        std::string extension = entry.path().extension().string();

        // Make sure we have a BIN extension. We don't want to accidentally read an assembly text file.
        if (extension != ".bin") {
            continue;
        }

        // Get the resource type from the filename.
        if (filename.find("_CODE_0") != std::string::npos) {
            code0_candidates.push_back(entry.path().string());

        } else if (filename.find("_DATA_0") != std::string::npos) {
            data0_candidates.push_back(entry.path().string());

        } else if (filename.find("_CODE_") != std::string::npos && filename.find(".bin") != std::string::npos) {
            // Extract segment number from filename (e.g., "App_CODE_1_ice.bin" -> 1).
            size_t code_pos = filename.find("_CODE_");
            size_t bin_pos = filename.find(".bin");
            if (code_pos != std::string::npos && bin_pos != std::string::npos) {
                std::string num_str = filename.substr(code_pos + 6, bin_pos - (code_pos + 6));
                try {
                    int segment_num = std::stoi(num_str);
                    if (segment_num > 0) {  // Only CODE 1+
                        code_segment_map[segment_num] = entry.path().string();
                    }
                } catch (...) {
                    // Invalid number, skip.
                }
            }
        }
    }

    // Validate that required resources exist.
    bool required_resources_found =
        code0_candidates.size() == 1 &&
        data0_candidates.size() == 1 &&
        code_segment_map.count(1) == 1;  // At least CODE 1 must exist

    if (!required_resources_found) {
        std::cerr << "ERROR: Missing or duplicate required resource files" << std::endl;
        std::cerr << "  Found " << code0_candidates.size() << " *_CODE_0.bin file(s)" << std::endl;
        std::cerr << "  Found " << data0_candidates.size() << " *_DATA_0.bin file(s)" << std::endl;
        std::cerr << "  Found " << code_segment_map.size() << " *_CODE_N.bin file(s)" << std::endl;
        std::cerr << "Exactly one matching resource file per segment is required:" << std::endl;
        std::cerr << "  *_CODE_0.bin" << std::endl;
        std::cerr << "  *_DATA_0.bin" << std::endl;
        std::cerr << "  *_CODE_1.bin (and optionally CODE_2.bin, CODE_3.bin, etc.)" << std::endl;
        return false;
    }

    // Extract basename from CODE_0 filename.
    std::string code0_filename = fs::path(code0_candidates[0]).filename().string();
    size_t suffix_pos = code0_filename.find("_CODE_0.bin");
    resources.basename = code0_filename.substr(0, suffix_pos);
    resources.code0_path = code0_candidates[0];
    resources.data0_path = data0_candidates[0];

    // Convert map to sorted vector.
    for (const auto& pair : code_segment_map) {
        CodeSegment seg;
        seg.segment_number = pair.first;
        seg.path = pair.second;
        seg.size = 0;  // Will be filled in later when we load the file
        resources.code_segments.push_back(seg);
    }

    std::cout << "Found resource files with basename: " << resources.basename << std::endl;
    std::cout << "  CODE_0: " << resources.code0_path << std::endl;
    std::cout << "  DATA_0: " << resources.data0_path << std::endl;
    for (const auto& seg : resources.code_segments) {
        std::cout << "  CODE_" << seg.segment_number << ": " << seg.path << std::endl;
    }

    return true;
}

int dump(const ResourceFiles& resources, const std::string& dump_filename) {
    const char* code0_file = resources.code0_path.c_str();
    const char* data0_file = resources.data0_path.c_str();
    const char* dump_file_cstr = dump_filename.c_str();

    // Use vectors for automatic memory management
    std::vector<char> code0_buffer;
    std::vector<char> data0_buffer;
    std::vector<std::vector<char>> code_segment_buffers;  // One buffer per CODE segment
    std::vector<char> a5_world_buffer;

    // Pointers that can be modified to read through the buffers
    char* data0_resource = nullptr;
    char* code0_resource = nullptr;
    void* a5_world_base = nullptr;

    uint32_t above_a5_size = 0;
    uint32_t below_a5_size = 0;
    uint32_t total_code_size = 0;

    // Load CODE 0 resource (jumptable).
    if (code0_file != NULL) {
        // Open the file.
        std::ifstream code0_stream(code0_file, std::ios::binary | std::ios::ate);
        if (!code0_stream.is_open()) {
            printf("ERROR: Cannot open CODE 0 resource file: %s\n", code0_file);
            return 1;
        }

        // Read the file.
        std::size_t file_size = code0_stream.tellg();
        code0_stream.seekg(0, std::ios::beg);
        code0_buffer.resize(file_size);
        code0_stream.read(code0_buffer.data(), file_size);
        if (!code0_stream || code0_stream.gcount() != static_cast<std::streamsize>(file_size)) {
            printf("ERROR: Failed to read CODE 0 resource file\n");
            return 1;
        }

        // Parse jumptable header (big-endian). Use pointer to read through buffer for now.
        // A stream really should be used, but at least it works.
        code0_resource = code0_buffer.data();
        above_a5_size = read_be32(code0_resource);
        code0_resource += 4;
        below_a5_size = read_be32(code0_resource);
        code0_resource += 4;
        uint32_t jump_table_size = read_be32(code0_resource);
        code0_resource += 4;
        uint32_t jump_table_offset = read_be32(code0_resource);
        code0_resource += 4;

        printf("Jumptable info:\n");
        printf("  Above A5 size: 0x%x (%u bytes)\n", above_a5_size, above_a5_size);
        printf("  Below A5 size: 0x%x (%u bytes)\n", below_a5_size, below_a5_size);
        printf("  Jump table size: 0x%x (%u bytes)\n", jump_table_size, jump_table_size);
        printf("  Jump table offset: 0x%x\n", jump_table_offset);
    }

    // Load DATA 0 resource (compressed A5 world).
    if (data0_file != NULL) {
        // Open the file.
        std::ifstream data0_stream(data0_file, std::ios::binary | std::ios::ate);
        if (!data0_stream.is_open()) {
            printf("ERROR: Cannot open DATA 0 resource file: %s\n", data0_file);
            return 1;
        }

        // Read the file.
        std::size_t file_size = data0_stream.tellg();
        data0_stream.seekg(0, std::ios::beg);
        data0_buffer.resize(file_size);
        data0_stream.read(data0_buffer.data(), file_size);
        if (!data0_stream || data0_stream.gcount() != static_cast<std::streamsize>(file_size)) {
            printf("ERROR: Failed to read DATA 0 resource file\n");
            return 1;
        }

        data0_resource = data0_buffer.data();
    }

    // Load all CODE segments from disk.
    code_segment_buffers.resize(resources.code_segments.size());
    std::vector<CodeSegment> code_segments = resources.code_segments;
    for (size_t i = 0; i < code_segments.size(); i++) {
        // Open the file.
        const std::string& code_file = code_segments[i].path;
        std::ifstream code_stream(code_file, std::ios::binary | std::ios::ate);
        if (!code_stream.is_open()) {
            printf("ERROR: Cannot open CODE %d resource file: %s\n",
                   code_segments[i].segment_number, code_file.c_str());
            return 1;
        }

        // Get file size.
        std::size_t file_size = code_stream.tellg();
        code_stream.seekg(0, std::ios::beg);
        if (file_size <= 0) {
            printf("ERROR: Invalid CODE %d resource file size: %ld\n",
                   code_segments[i].segment_number, file_size);
            return 1;
        }

        code_segments[i].size = file_size;
        total_code_size += file_size;

        // Read the file.
        code_segment_buffers[i].resize(file_size);
        code_stream.read(code_segment_buffers[i].data(), file_size);
        if (!code_stream || code_stream.gcount() != static_cast<std::streamsize>(file_size)) {
            printf("ERROR: Failed to read CODE %d resource file\n",
                   code_segments[i].segment_number);
            return 1;
        }
    }

    // Check that CODE 1 starts with the expected instructions. This is a guard against creating a junk dump
    // by trying to decompress and relocate stuff that isn't actually part of a CodeWarrior binary.
    const unsigned char expected_code1_start[] = {
        // NOTE: We are assuming that CODE 1 always has these jumptable fields, but this might not always be true.
        0x00, 0x00,                          // A5 relative offset of this segment's jump table
        0x00, 0x01,                          // number of entries in this segment's jump table

        0x9D, 0xCE,                         // sub.l A6, A6
        0x59, 0x8F,                         // subq.l A7, 4
        0x2F, 0x3C, 0x43, 0x4F, 0x44, 0x45, // move.l -[A7], 0x434F4445 ('CODE')
        0x42, 0x67,                         // clr.w -[A7]
        0xA9, 0xA0                          // syscall GetResource
    };
    const size_t expected_code1_start_length = sizeof(expected_code1_start);
    bool is_codewarrior = false;
    if (code_segments.size() > 0 && code_segments[0].segment_number == 1) {
        if (code_segment_buffers[0].size() >= expected_code1_start_length) {
            const unsigned char* code1_start = reinterpret_cast<const unsigned char*>(code_segment_buffers[0].data());
            is_codewarrior = (memcmp(code1_start, expected_code1_start, expected_code1_start_length) == 0);
        }
    }
    if (!is_codewarrior) {
        printf("FATAL: CODE 1 does not start with expected CodeWarrior startup code. This might not be a CodeWarrior application.");
        exit(2);
    }

    // Now, actually dump all code segments.
    std::vector<char*> segment_buffer_ptrs(code_segment_buffers.size());
    for (size_t i = 0; i < code_segment_buffers.size(); i++) {
        segment_buffer_ptrs[i] = code_segment_buffers[i].data();
    }
    a5_world_base = __Startup__(data0_resource, code_segments, above_a5_size, below_a5_size, segment_buffer_ptrs.data());
    if (a5_world_base == nullptr) {
        printf("ERROR: A5 world setup failed\n");
        return 1;
    }
    const long total_dump_size = code_resource_offset + total_code_size;
    a5_world_buffer.resize(total_dump_size);
    std::memcpy(a5_world_buffer.data(), a5_world_base, total_dump_size);
    free(a5_world_base);  // Free the malloc'd memory from __Startup__
    a5_world_base = nullptr;

    // Write out the dump file.
    std::ofstream dump_output(dump_file_cstr, std::ios::binary);
    if (!dump_output.is_open()) {
        printf("ERROR: Cannot create dump file: %s\n", dump_file_cstr);
        return 1;
    }
    dump_output.write(a5_world_buffer.data(), total_dump_size);
    bool write_success = dump_output.good();
    dump_output.close();
    if (!write_success) {
        printf("ERROR: Failed to write complete memory dump\n");
        return 1;
    }

    printf("%zu bytes written to %s\n", (size_t)total_dump_size, dump_file_cstr);
    return 0;
}

// Load a segment into memory and relocate it.
// It is not relevant for creating a dump, but the original seems to totally
// override the system _LoadSeg and never call it from inside the app.
static int __LoadSeg__(
    int16_t segment_number, char *code_resource, uint32_t code_size,
    uint32_t a5_base, uint32_t code_base, char *code_dest, char *dump_base) {
    // Parse segment header from CODE resource.
    // It seems that only CODE 2 and on have this header. CODE 1 has an abbreviated 4-byte header, which is one
    // of the reasons why it is loaded directly in __Startup__ and not by this function.
    printf("\n*** %s: LOADING CODE SEGMENT %d ***\n", __func__, segment_number);
    SegmentHeader header;
    header.jtsoffset = (int16_t)read_be16(code_resource + 0);
    header.jtentries = (int16_t)read_be16(code_resource + 2);
    // The original seems to only use the long version.
    header.jtloffset = (int32_t)read_be32(code_resource + 4);
    header.xrefoffset = (int32_t)read_be32(code_resource + 8);
    printf("Segment header:\n");
    printf("  jtsoffset:   0x%04x (%d)\n", header.jtsoffset, header.jtsoffset);
    printf("  jtentries:   %d\n", header.jtentries);
    printf("  jtloffset:   0x%08x\n", header.jtloffset);
    printf("  xrefoffset:  0x%08x\n", header.xrefoffset);

    // Append code to dump. Note that the header is INCLUDED as part of the dump.
    printf("Copying CODE resource (%u bytes) to 0x%x\n", code_size, code_base);
    memcpy(code_dest, code_resource, code_size);

    // Relocate this segment.
    char* xref_ptr = code_dest + header.xrefoffset;
    printf("Relocating segment at 0x%x\n", code_base);
    __relocate__(xref_ptr, code_dest, a5_base, code_base);

    // Update jump table entries to the loaded format. We need this because Ghidra needs to be able to resolve intersegment
    // references. As described at Classic 68K Runtime Architecture, "A call that goes through the jump table has the form
    //  JSR offset (A5)
    // where offset is the offset of the jump table entry for the routine from A5 plus 2 bytes." (Though note that the CodeWarrior
    // jumptable format does not require the added 2 bytes!)
    // We need to morph the unloaded jump table entry into its loaded form.

    // The jumptable is at A5 + jtloffset (using long version). jtloffset should never be negative, because "negative offsets
    // from A5 reference global variables, while positive offsets that are greater than 32 refer to jump-table entries."
    char* a5_ptr = dump_base + a5_base;
    char* jumptable_ptr = a5_ptr + header.jtloffset;
    printf("Updating jump table: %d entries at offset 0x%08x\n", header.jtentries, header.jtloffset);

    for (int i = 0; i < header.jtentries; i++) {
        // Read current (unloaded) jump table entry. Recall this is NOT the standard Mac jumptable format.
        // TODO: Also handle far model jump tables, where the unloaded segment format is different.
        // BEFORE (unloaded):
        //   entry.jumpinstruction = 0xA9F0  // _LoadSeg trap number
        //   entry.jumpaddress = offset      // offset from segment base
        //   entry.segment = N               // segment number
        const uint16_t LOADSEG_TRAP_NUMBER = 0xA9F0;
        JumpTableEntry* entry = (JumpTableEntry*)(jumptable_ptr + i * sizeof(JumpTableEntry));
        uint16_t old_instruction = read_be16((char*)&entry->jumpinstruction);
        if (old_instruction != LOADSEG_TRAP_NUMBER) {
            printf("WARNING: Unexpected jump table instruction: %04x\n", old_instruction);
        }
        int32_t old_address = (int32_t)read_be32((char*)&entry->jumpaddress);
        uint16_t segment = read_be16((char*)&entry->segment);

        // Transform this to a loaded jumptable entry.
        // AFTER (loaded):
        //   entry.jumpinstruction = 0x4EF9 (absolute long jump)
        //   entry.absolute_address = segmentBase + old_offset
        //   entry.segment = N (still there but unused when loaded)
        const uint16_t ABSOLUTE_LONG_JUMP_OPCODE = 0x4EF9;
        write_be16((char*)&entry->jumpinstruction, ABSOLUTE_LONG_JUMP_OPCODE);
        // Make segment base point to where this segment actually lives in our dump.
        // This is the immediate arg for the absolute jump, which is exactly what Ghidra needs.
        int32_t new_address = old_address + code_base;
        write_be32((char*)&entry->jumpaddress, new_address);
        // Segment number stays the same.
        write_be16((char*)&entry->segment, segment);

        printf("  Entry %d (0x%x): 0x%08x -> 0x%08x\n",
               i, segment, old_address, new_address);
    }

    printf("*** %s: CODE SEGMENT %d LOADED ***\n\n", __func__, segment_number);
    return 0;
}

/****************************************************************/
/* Purpose..: The Startup routine for Applications		*/
/* Input....: data0_resource - pointer to DATA 0 resource      */
/* Input....: code_segments - vector of all CODE segments      */
/* Input....: above_a5_size, below_a5_size - A5 world sizes    */
/* Input....: segment_buffers - array of pointers to segment data */
/* Returns..: pointer to allocated and relocated dump          */
/****************************************************************/
void* __Startup__(
    char *data0_resource, std::vector<CodeSegment>& code_segments,
    uint32_t above_a5_size, uint32_t below_a5_size, char* segment_buffers[])
{
    // Calculate total size needed for all CODE segments.
    uint32_t total_code_size = 0;
    for (const auto& seg : code_segments) {
        total_code_size += seg.size;
    }

	// Allocate memory for the entire dump (A5 world + all CODE resources).
    const uint32_t total_a5_world_size = below_a5_size + above_a5_size;
    const uint32_t total_dump_size = code_resource_offset + total_code_size;
    char* dump_base = (char*)malloc(total_dump_size);
    if (dump_base == NULL) {
        return NULL;
    }
    memset(dump_base, 0, total_dump_size);

    // Calculate A5 position within the allocated memory.
    char* a5_ptr = dump_base + below_a5_size;
	uint32_t a5_unrelocated = below_a5_size;

    // Initialize global data area from DATA 0 resource.
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

        // Decompress initialization data into A5 world.
        char* init_data_ptr = data0_ptr + 4;  // Skip CODE 1 xrefs offset.
        char* xref_data_ptr = __decomp_data__(init_data_ptr, a5_ptr);

        // Relocate the DATA segment (A5 world).
        printf("\n*** %s: RELOCATE DATA 0 (A5 world) ***\n", __func__);
        uint32_t code1_unrelocated = code_resource_offset;  // CODE 1 always starts here
        xref_data_ptr = __relocate__(xref_data_ptr, a5_ptr, a5_unrelocated, code1_unrelocated);

        // Load and relocate all CODE segments.
        uint32_t current_code_offset = code_resource_offset;
        for (size_t i = 0; i < code_segments.size(); i++) {
            const CodeSegment& seg = code_segments[i];
            char* code_dest = dump_base + current_code_offset;

            if (seg.segment_number == 1) {
                // CODE 1: Direct relocation.
                printf("Copying CODE 1 resource (%u bytes) to dump at offset 0x%x\n",
                       seg.size, current_code_offset);
                memcpy(code_dest, segment_buffers[i], seg.size);

                printf("\n*** %s: RELOCATE CODE SEGMENT 1 ***\n", __func__);
                xref_data_ptr = __relocate__(xref_data_ptr, code_dest, a5_unrelocated, code1_unrelocated);
            } else {
                // CODE 2+: Use __LoadSeg__ for proper segment loading.
                int result = __LoadSeg__(seg.segment_number, segment_buffers[i], seg.size, a5_unrelocated, current_code_offset, code_dest, dump_base);
                if (result != 0) {
                    free(dump_base);
                    return NULL;
                }
            }

            current_code_offset += seg.size;
        }

        printf("A5 register: 0x%x\n", below_a5_size);
        printf("Below A5: 0x%x bytes\n", below_a5_size);
        printf("Above A5: 0x%x bytes\n", above_a5_size);
        printf("Total A5 world size: 0x%x bytes\n", total_a5_world_size);
        printf("Total CODE segments size: 0x%x bytes (%zu segments)\n", total_code_size, code_segments.size());
        printf("Total dump size: 0x%x bytes\n", total_dump_size);
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
		int32_t offset = (int32_t)read_be32(ptr);
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
static char *__reloc_compr__(char *ptr,char *segment, uint32_t relocbase, uint32_t a5_base)
{
	int32_t	offset;
	uint32_t relocations;
	char	c;

	relocations = read_be32(ptr);
	ptr += 4;

	printf("Relocating %u references (base 0x%x)\n", relocations, relocbase);
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
				int16_t word_val = read_be16(ptr - 1);  // c is first byte, read second byte
				ptr++;
				offset+=(int16_t)(word_val<<2)>>1;
			}
			else
			{	//	direct signed 31-bit offset
				int32_t lword_val = read_be32(ptr - 1);  // c is first byte, read remaining 3 bytes
				ptr += 3;
				offset=(lword_val<<2)>>1;
			}
		}

		// Get the current value before relocation (big-endian)
		char *position = segment + offset;
		uint32_t unrelocated_value = read_be32(position);

		// Perform the relocation and write back in big-endian format
		uint32_t relocated_value = unrelocated_value + relocbase;
		write_be32(position, relocated_value);

		// Log the relocation details
		printf("  Offset 0x%X + 0x%X = 0x%X: 0x%X + 0x%X = 0x%X\n",
			(uint32_t)offset,
			a5_base,
			(uint32_t)(offset + a5_base),
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
static char *__relocate__(char *xref, char *segm, uint32_t a5_base, uint32_t code1_base)
{
	char *ptr = xref;

	// Relocate references to DATA segment (A5).
	printf("Relocating references to A5 world (DATA 0)...\n");
	ptr = __reloc_compr__(ptr, segm, a5_base, a5_base);

	// Relocate references to CODE segment 1.
	printf("Relocating references to CODE 1...\n");
	ptr = __reloc_compr__(ptr, segm, code1_base, a5_base);

	// Relocate references to same CODE segment.
	// TODO: Understand what this actually is.
	printf("Relocating internal references...\n");
	ptr = __reloc_compr__(ptr, segm, (long)segm, a5_base);

	return ptr;
}
