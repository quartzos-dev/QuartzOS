
#define MAX_WINDOWS 5
#define MAX_WORKSPACES 4
#define FEATURE_CATEGORY_COUNT 12
#define FEATURES_PER_CATEGORY 80
#define FEATURE_TOTAL (FEATURE_CATEGORY_COUNT * FEATURES_PER_CATEGORY)
#define FEATURE_ROWS_PER_PAGE 12
#define FEATURE_MAX_NAME 80
#define FEATURE_CATEGORY_ALL FEATURE_CATEGORY_COUNT

#define LAUNCHER_MAX_APPS 1200
#define LAUNCHER_APP_NAME_MAX 64
#define LAUNCHER_ROWS_PER_PAGE 14

#define NOTIFY_MAX 24
#define NOTIFY_TEXT_MAX 96

enum {
    LAUNCHER_CAT_ALL = 0,
    LAUNCHER_CAT_NATIVE = 1,
    LAUNCHER_CAT_ECOSYSTEM = 2
};

#define TOP_BAR_H 28
#define DOCK_H 72
#define DOCK_BOTTOM_PAD 8
#define DOCK_SIDE_PAD 18
#define DOCK_ICON_W 54
#define DOCK_ICON_H 54
#define DOCK_ICON_GAP 14
#define TITLE_H 24
#define FRAME_TARGET_TICKS 1
#define FILE_CACHE_TICKS 120

enum {
    SNAP_NONE = 0,
    SNAP_MAX = 1,
    SNAP_LEFT = 2,
    SNAP_RIGHT = 3
};

enum {
    RESIZE_NONE = 0,
    RESIZE_RIGHT = 1,
    RESIZE_BOTTOM = 2,
    RESIZE_CORNER = 3,
    RESIZE_LEFT = 4,
    RESIZE_TOP = 5
};

typedef enum window_kind {
    WINDOW_MONITOR = 0,
    WINDOW_TERMINAL = 1,
    WINDOW_FILES = 2,
    WINDOW_NETWORK = 3,
    WINDOW_SECURITY = 4
} window_kind_t;

typedef struct window {
    int x;
    int y;
    int w;
    int h;
    int prev_x;
    int prev_y;
    int prev_w;
    int prev_h;
    uint32_t color;
    char title[32];
    window_kind_t kind;
    int workspace;
    int visible;
    int minimized;
    int maximized;
} window_t;

typedef struct start_item {
    const char *label;
    int action;
} start_item_t;

typedef struct gui_notification {
    char text[NOTIFY_TEXT_MAX];
    uint32_t color;
    uint64_t tick;
} gui_notification_t;

enum {
    START_ACTION_MONITOR = 0,
    START_ACTION_TERMINAL = 1,
    START_ACTION_FILES = 2,
    START_ACTION_NETWORK = 3,
    START_ACTION_SECURITY = 4,
    START_ACTION_OPEN_LAUNCHER = 5,
    START_ACTION_OPEN_FEATURE_HUB = 6,
    START_ACTION_OPEN_QUICK_PANEL = 7,
    START_ACTION_OVERLAY = 8,
    START_ACTION_RESTORE_ALL = 9,
    START_ACTION_CLOSE_ALL = 10
};

static const start_item_t start_items[] = {
    {"Application Launcher", START_ACTION_OPEN_LAUNCHER},
    {"Feature Center (960)", START_ACTION_OPEN_FEATURE_HUB},
    {"Quick Settings", START_ACTION_OPEN_QUICK_PANEL},
    {"System Monitor", START_ACTION_MONITOR},
    {"Terminal", START_ACTION_TERMINAL},
    {"File Explorer", START_ACTION_FILES},
    {"Network", START_ACTION_NETWORK},
    {"Security Center", START_ACTION_SECURITY},
    {"Toggle CLI Overlay", START_ACTION_OVERLAY},
    {"Restore All Windows", START_ACTION_RESTORE_ALL},
    {"Close All Windows", START_ACTION_CLOSE_ALL}
};

static window_t windows[MAX_WINDOWS];
static int window_count;

static int active_index = -1;
static int drag_index = -1;
static int drag_dx;
static int drag_dy;
static int drag_snap_mode;
static int resize_index = -1;
static int resize_mode;
static int resize_origin_x;
static int resize_origin_y;
static int resize_origin_w;
static int resize_origin_h;
static int resize_origin_mouse_x;
static int resize_origin_mouse_y;
static uint64_t last_title_click_tick;
static int last_title_click_index = -1;
static int current_workspace;

static int overlay;
static int overlay_prev;
static int start_menu_open;
static int context_menu_open;
static int context_menu_x;
static int context_menu_y;
static int show_desktop_mode;
static int desktop_hidden[MAX_WINDOWS];
static int launcher_open;
static int launcher_category;
static int launcher_page;
static int launcher_selected;
static int launcher_count;
static int launcher_index_view[LAUNCHER_MAX_APPS];
static char launcher_apps[LAUNCHER_MAX_APPS][LAUNCHER_APP_NAME_MAX];
static uint64_t launcher_last_refresh_tick;
static int feature_hub_open;
static int feature_category;
static int feature_page;
static int feature_selected;
static uint8_t feature_enabled[FEATURE_TOTAL];
static int quick_panel_open;
static int notifications_open;
static gui_notification_t notifications[NOTIFY_MAX];
static int notify_count;
static int notify_write_idx;

static int mouse_prev_left;
static int mouse_prev_right;
static int mouse_prev_x;
static int mouse_prev_y;
static int cursor_prev_valid;
static int cursor_prev_x;
static int cursor_prev_y;
static int cursor_prev_w;
static int cursor_prev_h;

static uint64_t last_frame_tick;
static uint64_t last_clock_sec;
static int need_redraw;
static char file_cache_root[192];
static char file_cache_bin[224];
static char file_cache_assets[224];
static uint64_t file_cache_tick;
static int file_cache_valid;
