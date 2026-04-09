
#include <steam/steam_api.h>
#include <new>

extern "C" {
    typedef void (*RustCallbackFn)(void*);
}

class RustCallback final : public CCallbackBase {
public:
    RustCallback(int size, bool game_server, RustCallbackFn fn)
        : size_(size), fn_(fn) {
        if (game_server)
            m_nCallbackFlags |= 0x02;
    }

    void Run(void* param) override {
        fn_(param);
    }

    void Run(
        void* param,
        bool io_failure,
        SteamAPICall_t api_call
    ) override {
        fn_(param);
    }

    int GetCallbackSizeBytes() override {
        return size_;
    }

private:
    int size_;
    RustCallbackFn fn_;
};

extern "C" CCallbackBase* rust_callback_create(
    int size,
    bool game_server,
    RustCallbackFn fn
) noexcept {
    if (!fn || size <= 0)
        return nullptr;

    return new (std::nothrow)
        RustCallback(size, game_server, fn);
}

extern "C" void rust_callback_destroy(
    CCallbackBase* callback
) noexcept {
    delete static_cast<RustCallback*>(callback);
}
