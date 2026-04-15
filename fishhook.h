#ifndef fishhook_h
#define fishhook_h

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);
int rebind_symbols_image(void *header, const char *slide, struct rebinding rebindings[], size_t rebindings_nel);

#ifdef __cplusplus
}
#endif

#endif /* fishhook_h */
