#include "fishhook.h"
#include <dlfcn.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static struct rebindings_entry {
    struct rebinding *rebindings;
    size_t rebindings_nel;
    struct rebindings_entry *next;
} *rebindings_head;

static int prepend_rebindings(struct rebindings_entry **head, struct rebinding rebindings[], size_t nel) {
    struct rebindings_entry *new_entry = (struct rebindings_entry *)malloc(sizeof(struct rebindings_entry));
    if (!new_entry) return -1;
    new_entry->rebindings = (struct rebinding *)malloc(sizeof(struct rebinding) * nel);
    if (!new_entry->rebindings) {
        free(new_entry);
        return -1;
    }
    memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
    new_entry->rebindings_nel = nel;
    new_entry->next = *head;
    *head = new_entry;
    return 0;
}

static struct section_64 *getsectiondata64(const struct mach_header_64 *mh, const char *segname, const char *sectname, uint64_t *size) {
    struct load_command *cmd = (struct load_command *)((uint8_t *)mh + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            if (strcmp(seg->segname, segname) == 0) {
                struct section_64 *sect = (struct section_64 *)((uint8_t *)seg + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strcmp(sect->sectname, sectname) == 0) {
                        *size = sect->size;
                        return sect;
                    }
                    sect = (struct section_64 *)((uint8_t *)sect + sizeof(struct section_64));
                }
            }
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }
    return NULL;
}

static void perform_rebinding_with_section(struct rebindings_entry *rebindings, struct section_64 *section, intptr_t slide, struct nlist_64 *symtab, char *strtab, uint32_t *indirect_symtab) {
    uint32_t *indirect_symbol_indices = (uint32_t *)((uint8_t *)slide + section->reserved1);
    void **indirect_symbol_bindings = (void **)((uint8_t *)slide + section->addr);
    uint32_t symbol_index;

    for (uint i = 0; i < section->size / sizeof(void *); i++) {
        symbol_index = indirect_symbol_indices[i];
        if (symbol_index == INDIRECT_SYMBOL_ABS || symbol_index == INDIRECT_SYMBOL_LOCAL || symbol_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
        uint32_t strtab_offset = symtab[symbol_index].n_un.n_strx;
        char *symbol_name = strtab + strtab_offset;
        struct rebindings_entry *cur = rebindings;
        while (cur) {
            for (uint j = 0; j < cur->rebindings_nel; j++) {
                if (strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    if (cur->rebindings[j].replaced && *cur->rebindings[j].replaced == NULL) {
                        *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
                    }
                    indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
                    goto symbol_loop;
                }
            }
            cur = cur->next;
        }
symbol_loop:;
    }
}

static void rebind_symbols_for_image(struct rebindings_entry *rebindings, const struct mach_header_64 *header, intptr_t slide) {
    uint64_t size = 0;
    struct load_command *cmd = (struct load_command *)((uint8_t *)header + sizeof(struct mach_header_64));
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cmd;
        } else if (cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cmd;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }
    if (!symtab_cmd || !dysymtab_cmd) return;

    char *strtab = (char *)((uint8_t *)header + symtab_cmd->stroff);
    struct nlist_64 *symtab = (struct nlist_64 *)((uint8_t *)header + symtab_cmd->symoff);
    struct section_64 *section = getsectiondata64(header, "__DATA", "__la_symbol_ptr", &size);
    if (section) {
        perform_rebinding_with_section(rebindings, section, slide, symtab, strtab, (uint32_t *)((uint8_t *)header + dysymtab_cmd->indirectsymoff));
    }
    section = getsectiondata64(header, "__DATA", "__nl_symbol_ptr", &size);
    if (section) {
        perform_rebinding_with_section(rebindings, section, slide, symtab, strtab, (uint32_t *)((uint8_t *)header + dysymtab_cmd->indirectsymoff));
    }
}

int rebind_symbols_image(void *header, const char *slide, struct rebinding rebindings[], size_t rebindings_nel) {
    struct rebindings_entry *cur = NULL;
    if (prepend_rebindings(&rebindings_head, rebindings, rebindings_nel) < 0) return -1;
    cur = rebindings_head;
    rebind_symbols_for_image(cur, (const struct mach_header_64 *)header, (intptr_t)slide);
    return 0;
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
    Dl_info info;
    if (dladdr((void *)rebind_symbols, &info) == 0) return -1;
    uint32_t image_count = _dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        rebind_symbols_image((void *)header, (const char *)slide, rebindings, rebindings_nel);
    }
    return 0;
}
