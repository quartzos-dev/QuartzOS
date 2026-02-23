#include <kernel/app_runtime.h>
#include <kernel/security.h>
#include <lib/string.h>
#include <process/user.h>
#include <stdint.h>

#define WRAP_MAGIC "QZWRAP1"
#define WRAP_MAGIC_LEN 7u
#define WRAP_TRAILER_LEN (WRAP_MAGIC_LEN + 1u + 8u)

#define ELF_MAGIC 0x464c457fU
#define ET_EXEC 2u
#define ET_DYN 3u
#define EM_X86_64 0x3Eu
#define PT_INTERP 3u
#define ELFCLASS64 2u
#define ELFDATA2LSB 1u

static uint16_t read_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t read_le64(const uint8_t *p) {
    return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

static void set_detail(app_runtime_info_t *out, const char *detail) {
    if (!out) {
        return;
    }
    out->detail[0] = '\0';
    if (detail && *detail) {
        strncpy(out->detail, detail, sizeof(out->detail) - 1);
        out->detail[sizeof(out->detail) - 1] = '\0';
    }
}

static int unwrap_payload(const uint8_t *image, size_t size,
                          char *kind, size_t *payload_off, size_t *payload_len) {
    if (!image || size < WRAP_TRAILER_LEN) {
        return 0;
    }

    size_t tail = size - WRAP_TRAILER_LEN;
    if (memcmp(image + tail, WRAP_MAGIC, WRAP_MAGIC_LEN) != 0) {
        return 0;
    }

    char k = (char)image[tail + WRAP_MAGIC_LEN];
    uint64_t len = read_le64(image + tail + WRAP_MAGIC_LEN + 1u);
    if (len == 0 || len > (uint64_t)tail) {
        return 0;
    }

    if (kind) {
        *kind = k;
    }
    if (payload_len) {
        *payload_len = (size_t)len;
    }
    if (payload_off) {
        *payload_off = tail - (size_t)len;
    }
    return 1;
}

static int probe_elf(const uint8_t *image, size_t size, app_runtime_info_t *out) {
    if (!image || size < 64u) {
        return 0;
    }
    if (read_le32(image) != ELF_MAGIC) {
        return 0;
    }

    if (image[4] != ELFCLASS64 || image[5] != ELFDATA2LSB) {
        if (out) {
            out->kind = APP_RUNTIME_LINUX_ELF;
            out->runnable = false;
            out->wrapped = false;
            set_detail(out, "unsupported ELF class/data");
        }
        return 1;
    }

    uint16_t e_type = read_le16(image + 16);
    uint16_t e_machine = read_le16(image + 18);
    uint8_t osabi = image[7];
    uint64_t phoff = read_le64(image + 32);
    uint16_t phentsize = read_le16(image + 54);
    uint16_t phnum = read_le16(image + 56);

    int has_interp = 0;
    if (phoff > 0 && phnum > 0 && phentsize >= 56u) {
        for (uint16_t i = 0; i < phnum; i++) {
            uint64_t off = phoff + (uint64_t)i * (uint64_t)phentsize;
            if (off + 4u > size) {
                break;
            }
            uint32_t p_type = read_le32(image + off);
            if (p_type == PT_INTERP) {
                has_interp = 1;
                break;
            }
        }
    }

    int linux_like = (osabi == 3u) || has_interp || (e_type == ET_DYN);

    if (out) {
        out->kind = linux_like ? APP_RUNTIME_LINUX_ELF : APP_RUNTIME_CUSTOM_ELF;
        out->wrapped = false;
        out->runnable = false;

        if (e_machine != EM_X86_64) {
            set_detail(out, "unsupported architecture");
        } else if (e_type != ET_EXEC) {
            set_detail(out, "only ET_EXEC is supported");
        } else if (has_interp) {
            set_detail(out, "dynamic loader ELF is unsupported");
        } else {
            out->runnable = true;
            set_detail(out, linux_like ? "linux static ELF compatibility" : "Quartz custom ELF");
        }
    }

    return 1;
}

const char *app_runtime_kind_name(app_runtime_kind_t kind) {
    switch (kind) {
        case APP_RUNTIME_CUSTOM_ELF: return "custom-elf";
        case APP_RUNTIME_LINUX_ELF: return "linux-elf";
        case APP_RUNTIME_WINDOWS_PE: return "windows-pe";
        case APP_RUNTIME_MACOS_MACHO: return "macos-macho";
        default: return "unknown";
    }
}

security_app_kind_t app_runtime_security_kind(app_runtime_kind_t kind) {
    switch (kind) {
        case APP_RUNTIME_CUSTOM_ELF: return SECURITY_APP_CUSTOM;
        case APP_RUNTIME_LINUX_ELF: return SECURITY_APP_LINUX;
        case APP_RUNTIME_WINDOWS_PE: return SECURITY_APP_WINDOWS;
        case APP_RUNTIME_MACOS_MACHO: return SECURITY_APP_MACOS;
        default: return SECURITY_APP_UNKNOWN;
    }
}

bool app_runtime_probe(const void *image_ptr, size_t size, app_runtime_info_t *out) {
    const uint8_t *image = (const uint8_t *)image_ptr;

    if (out) {
        out->kind = APP_RUNTIME_UNKNOWN;
        out->wrapped = false;
        out->runnable = false;
        set_detail(out, "unknown format");
    }

    if (!image || size < 4u) {
        return false;
    }

    char wrap_kind = 0;
    size_t payload_off = 0;
    size_t payload_len = 0;
    if (unwrap_payload(image, size, &wrap_kind, &payload_off, &payload_len)) {
        if (out) {
            out->wrapped = true;
            out->runnable = false;
            switch (wrap_kind) {
                case 'W': out->kind = APP_RUNTIME_WINDOWS_PE; break;
                case 'M': out->kind = APP_RUNTIME_MACOS_MACHO; break;
                case 'L': out->kind = APP_RUNTIME_LINUX_ELF; break;
                case 'Q': out->kind = APP_RUNTIME_CUSTOM_ELF; break;
                default: out->kind = APP_RUNTIME_UNKNOWN; break;
            }

            if (payload_len >= 4u && read_le32(image + payload_off) == ELF_MAGIC) {
                out->runnable = true;
                set_detail(out, "wrapped Quartz payload");
            } else {
                set_detail(out, "wrapped payload missing ELF body");
            }
        }
        return true;
    }

    if (size >= 2u && image[0] == 'M' && image[1] == 'Z') {
        if (out) {
            out->kind = APP_RUNTIME_WINDOWS_PE;
            set_detail(out, "native PE requires wrapped Quartz payload");
        }
        return true;
    }

    if (size >= 4u) {
        uint32_t magic = read_le32(image);
        if (magic == 0xfeedfacfu || magic == 0xcffaedfeu) {
            if (out) {
                out->kind = APP_RUNTIME_MACOS_MACHO;
                set_detail(out, "native Mach-O requires wrapped Quartz payload");
            }
            return true;
        }
    }

    if (probe_elf(image, size, out)) {
        return true;
    }

    return false;
}

bool app_runtime_run(const void *image_ptr, size_t size, app_runtime_info_t *out) {
    const uint8_t *image = (const uint8_t *)image_ptr;
    app_runtime_info_t info;
    info.kind = APP_RUNTIME_UNKNOWN;
    info.wrapped = false;
    info.runnable = false;
    set_detail(&info, "unknown format");

    if (!app_runtime_probe(image, size, &info)) {
        if (out) {
            *out = info;
        }
        return false;
    }

    char deny_reason[96];
    deny_reason[0] = '\0';
    if (!security_allow_app_launch(app_runtime_security_kind(info.kind), info.wrapped,
                                   deny_reason, sizeof(deny_reason))) {
        info.runnable = false;
        if (deny_reason[0]) {
            set_detail(&info, deny_reason);
        } else {
            set_detail(&info, "blocked by security policy");
        }
        if (out) {
            *out = info;
        }
        return false;
    }

    if (info.wrapped) {
        char wrap_kind = 0;
        size_t payload_off = 0;
        size_t payload_len = 0;
        if (!unwrap_payload(image, size, &wrap_kind, &payload_off, &payload_len)) {
            info.runnable = false;
            set_detail(&info, "invalid wrapper trailer");
            if (out) {
                *out = info;
            }
            return false;
        }
        if (read_le32(image + payload_off) != ELF_MAGIC) {
            info.runnable = false;
            set_detail(&info, "wrapper payload is not ELF");
            if (out) {
                *out = info;
            }
            return false;
        }
        info.runnable = true;
        if (!user_run_elf(image + payload_off, payload_len)) {
            set_detail(&info, "wrapped payload launch failed");
            if (out) {
                *out = info;
            }
            return false;
        }
        if (out) {
            *out = info;
        }
        return true;
    }

    if (!info.runnable) {
        if (out) {
            *out = info;
        }
        return false;
    }

    if (!user_run_elf(image, size)) {
        set_detail(&info, "ELF launch failed");
        if (out) {
            *out = info;
        }
        return false;
    }

    if (out) {
        *out = info;
    }
    return true;
}
