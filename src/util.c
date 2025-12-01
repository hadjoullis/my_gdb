#include <util.h>

void load_ELF(char *filename, function_t **functions) {

    Elf *elf;
    /* Initilization.*/
    if (elf_version(EV_CURRENT) == EV_NONE) {
        die("(version) %s", elf_errmsg(-1));
    }

    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        die("opening file %s", filename);
    }

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        die("(begin) %s", elf_errmsg(-1));
    }

    check_symtab(elf, functions);
}

void check_symtab(Elf *elf, function_t **functions) {
    Elf_Scn *scn = get_elf_section(elf, ".symtab");
    if (scn == NULL) {
        *functions = NULL;
        return;
    }

    Elf_Data *data = NULL;
    data = elf_getdata(scn, NULL);

    GElf_Shdr shdr;
    if (gelf_getshdr(scn, &shdr) != &shdr) {
        die("(getshdr) %s", elf_errmsg(-1));
    }

    int count = shdr.sh_size / shdr.sh_entsize;
    int func_cnt = 0;

    for (int i = 0; i < count; i++) {
        GElf_Sym sym;
        gelf_getsym(data, i, &sym);
        if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC) {
            func_cnt++;
        }
    }

    *functions = malloc((func_cnt + 1) * sizeof(function_t));
    if (*functions == NULL) {
        die("allocating function info");
    }
    (*functions)[func_cnt].func_name = NULL;

    for (int i = 0, j = 0; i < count; i++) {
        GElf_Sym sym;
        gelf_getsym(data, i, &sym);
        if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC) {
            (*functions)[j].addr = sym.st_value;
            (*functions)[j].func_name =
                elf_strptr(elf, shdr.sh_link, sym.st_name);
            j++;
        }
    }
}

Elf_Scn *get_elf_section(Elf *elf, char *section) {

    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;

    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        die("(getshdrstrndx) %s", elf_errmsg(-1));

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));

        if (strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), section) == 0) {
            return scn;
        }
    }

    return NULL;
}
