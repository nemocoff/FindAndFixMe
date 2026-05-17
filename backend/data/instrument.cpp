#include <stdio.h>

extern "C" {
    void __cyg_profile_func_enter(void *this_fn, void *call_site) __attribute__((no_instrument_function));
    void __cyg_profile_func_exit(void *this_fn, void *call_site) __attribute__((no_instrument_function));

    static int event_count = 0;
    const int MAX_EVENTS = 500;

    void __cyg_profile_func_enter(void *this_fn, void *call_site) {
        if (event_count++ > MAX_EVENTS) return;
        fprintf(stderr, "[ENTER] %p\n", this_fn);
    }

    void __cyg_profile_func_exit(void *this_fn, void *call_site) {
        if (event_count++ > MAX_EVENTS) return;
        fprintf(stderr, "[EXIT] %p\n", this_fn);
    }
}
