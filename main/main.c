#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "bsp/device.h"
#include "bsp/display.h"
#include "bsp/input.h"
#include "bsp/power.h"
#include "bsp/led.h"
#include "driver/gpio.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_hosted_custom.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_types.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "hal/lcd_types.h"
#include "host/port/sdio_wrapper.h"
#include "nvs_flash.h"
#include "pax_fonts.h"
#include "pax_gfx.h"
#include "pax_text.h"
#include "portmacro.h"
#include "regex.h"
#include "sdkconfig.h"
#include "wifi_connection.h"

//Wifi stuff
#define DEFAULT_SCAN_LIST_SIZE 20

// Constants
static char const TAG[] = "main";

// Global variables
static size_t                       display_h_res        = 0;
static size_t                       display_v_res        = 0;
static lcd_color_rgb_pixel_format_t display_color_format = LCD_COLOR_PIXEL_FORMAT_RGB565;
static lcd_rgb_data_endian_t        display_data_endian  = LCD_RGB_DATA_ENDIAN_LITTLE;
static pax_buf_t                    fb                   = {0};
static QueueHandle_t                input_event_queue    = NULL;

#if defined(CONFIG_BSP_TARGET_KAMI)
static pax_col_t palette[] = {0xffffffff, 0xff000000, 0xffff0000};  // white, black, red
#endif

void blit(void) {
    bsp_display_blit(0, 0, display_h_res, display_v_res, pax_buf_get_pixels(&fb));
}

static bool initialized = false;

bool wifi_remote_get_initialized(void) {
    return initialized;
}

static esp_err_t wifi_remote_verify_radio_ready(void) {
    void* card = hosted_sdio_init();
    if (card == NULL) {
        ESP_LOGE(TAG, "Failed to initialize SDIO for radio");
        return ESP_FAIL;
    }
    esp_err_t res = hosted_sdio_card_init(NULL);
    if (res == ESP_OK) {
        ESP_LOGI(TAG, "Radio ready");
    } else {
        ESP_LOGI(TAG, "Radio not ready");
    }
    return res;
}

esp_err_t wifi_remote_initialize(void) {
    if (initialized) {
        return ESP_OK;
    }
    ESP_LOGW(TAG, "Switching radio off...\r\n");
    bsp_power_set_radio_state(BSP_POWER_RADIO_STATE_OFF);
    vTaskDelay(pdMS_TO_TICKS(50));
    ESP_LOGW(TAG, "Switching radio to application mode...\r\n");
    bsp_power_set_radio_state(BSP_POWER_RADIO_STATE_APPLICATION);
    vTaskDelay(pdMS_TO_TICKS(1000));
    ESP_LOGW(TAG, "Testing connection to radio...\r\n");
    if (wifi_remote_verify_radio_ready() != ESP_OK) {
        return ESP_ERR_INVALID_STATE;
    }
    ESP_LOGW(TAG, "Starting ESP hosted...\r\n");
    esp_hosted_host_init();
    initialized = true;
    return ESP_OK;
}

static void print_auth_mode(int authmode)
{
    switch (authmode) {
    case WIFI_AUTH_OPEN:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_OPEN");
        break;
    case WIFI_AUTH_OWE:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_OWE");
        break;
    case WIFI_AUTH_WEP:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WEP");
        break;
    case WIFI_AUTH_WPA_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA_PSK");
        break;
    case WIFI_AUTH_WPA2_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA2_PSK");
        break;
    case WIFI_AUTH_WPA_WPA2_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA_WPA2_PSK");
        break;
    case WIFI_AUTH_ENTERPRISE:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_ENTERPRISE");
        break;
    case WIFI_AUTH_WPA3_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA3_PSK");
        break;
    case WIFI_AUTH_WPA2_WPA3_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA2_WPA3_PSK");
        break;
    case WIFI_AUTH_WPA3_ENTERPRISE:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA3_ENTERPRISE");
        break;
    case WIFI_AUTH_WPA2_WPA3_ENTERPRISE:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA2_WPA3_ENTERPRISE");
        break;
    case WIFI_AUTH_WPA3_ENT_192:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA3_ENT_192");
        break;
    default:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_UNKNOWN");
        break;
    }
}

static void print_cipher_type(int pairwise_cipher, int group_cipher)
{
    switch (pairwise_cipher) {
    case WIFI_CIPHER_TYPE_NONE:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_NONE");
        break;
    case WIFI_CIPHER_TYPE_WEP40:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_WEP40");
        break;
    case WIFI_CIPHER_TYPE_WEP104:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_WEP104");
        break;
    case WIFI_CIPHER_TYPE_TKIP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_TKIP");
        break;
    case WIFI_CIPHER_TYPE_CCMP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_CCMP");
        break;
    case WIFI_CIPHER_TYPE_TKIP_CCMP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_TKIP_CCMP");
        break;
    case WIFI_CIPHER_TYPE_AES_CMAC128:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_AES_CMAC128");
        break;
    case WIFI_CIPHER_TYPE_SMS4:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_SMS4");
        break;
    case WIFI_CIPHER_TYPE_GCMP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_GCMP");
        break;
    case WIFI_CIPHER_TYPE_GCMP256:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_GCMP256");
        break;
    default:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_UNKNOWN");
        break;
    }

    switch (group_cipher) {
    case WIFI_CIPHER_TYPE_NONE:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_NONE");
        break;
    case WIFI_CIPHER_TYPE_WEP40:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_WEP40");
        break;
    case WIFI_CIPHER_TYPE_WEP104:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_WEP104");
        break;
    case WIFI_CIPHER_TYPE_TKIP:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_TKIP");
        break;
    case WIFI_CIPHER_TYPE_CCMP:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_CCMP");
        break;
    case WIFI_CIPHER_TYPE_TKIP_CCMP:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_TKIP_CCMP");
        break;
    case WIFI_CIPHER_TYPE_SMS4:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_SMS4");
        break;
    case WIFI_CIPHER_TYPE_GCMP:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_GCMP");
        break;
    case WIFI_CIPHER_TYPE_GCMP256:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_GCMP256");
        break;
    default:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_UNKNOWN");
        break;
    }
}

static void wifi_scan(void)
{
    ESP_LOGI(TAG, "************* Before init netif *************");
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_LOGI(TAG, "************* Netif init, before loop create *************");
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_LOGI(TAG, "************* Loop created. Before getting defailt wifi sta *************");
    esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
    assert(sta_netif);
    ESP_LOGI(TAG, "************* Got sta_netif. Before wifi cfg init *************");

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t err = esp_wifi_init(&cfg);
    if (err != ESP_OK) {
        printf("ERROR configuring wifi %d\n", err);
        return;
    }
    // ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_LOGI(TAG, "************* Wifi CFG ok. Before setting mode *************");

    uint16_t number = DEFAULT_SCAN_LIST_SIZE;
    wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
    uint16_t ap_count = 0;
    memset(ap_info, 0, sizeof(ap_info));


    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_LOGI(TAG, "************* Set mode done. Before starting wifi *************");
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "************* Wifi started. Before scanning *************");

// #ifdef USE_CHANNEL_BITMAP
//     wifi_scan_config_t *scan_config = (wifi_scan_config_t *)calloc(1,sizeof(wifi_scan_config_t));
//     if (!scan_config) {
//         ESP_LOGE(TAG, "Memory Allocation for scan config failed!");
//         return;
//     }
//     array_2_channel_bitmap(channel_list, CHANNEL_LIST_SIZE, scan_config);
//     esp_wifi_scan_start(scan_config, true);
//     free(scan_config);

// #else
    esp_wifi_scan_start(NULL, true);
// #endif /*USE_CHANNEL_BITMAP*/

    ESP_LOGI(TAG, "Max AP number ap_info can hold = %u", number);
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
    ESP_LOGI(TAG, "Total APs scanned = %u, actual AP number ap_info holds = %u", ap_count, number);
    for (int i = 0; i < number; i++) {
        ESP_LOGI(TAG, "SSID \t\t%s", ap_info[i].ssid);
        ESP_LOGI(TAG, "RSSI \t\t%d", ap_info[i].rssi);
        print_auth_mode(ap_info[i].authmode);
        if (ap_info[i].authmode != WIFI_AUTH_WEP) {
            print_cipher_type(ap_info[i].pairwise_cipher, ap_info[i].group_cipher);
        }
        ESP_LOGI(TAG, "Channel \t\t%d", ap_info[i].primary);
    }
}

static inline void wifi_desc_record(wifi_ap_record_t* record) {
    // Make a string representation of BSSID.
    char* bssid_str = malloc(3 * 6);
    if (!bssid_str) return;
    snprintf(bssid_str, 3 * 6, "%02X:%02X:%02X:%02X:%02X:%02X", record->bssid[0], record->bssid[1], record->bssid[2],
             record->bssid[3], record->bssid[4], record->bssid[5]);

    // Make a string representation of 11b/g/n modes.
    char* phy_str = malloc(9);
    if (!phy_str) {
        free(bssid_str);
        return;
    }
    *phy_str = 0;
    if (record->phy_11b | record->phy_11g | record->phy_11n) {
        strcpy(phy_str, " 1");
    }
    if (record->phy_11b) {
        strcat(phy_str, "/b");
    }
    if (record->phy_11g) {
        strcat(phy_str, "/g");
    }
    if (record->phy_11n) {
        strcat(phy_str, "/n");
    }
    phy_str[2] = '1';

    printf("AP %s %s rssi=%hhd%s\r\n", bssid_str, record->ssid, record->rssi, phy_str);
    free(bssid_str);
    free(phy_str);
}

static esp_err_t scan_for_networks(wifi_ap_record_t** out_aps, uint16_t* out_aps_length) {
    if (wifi_remote_get_initialized()) {
        esp_err_t res;

        wifi_config_t wifi_config = {0};
        ESP_LOGI(TAG, "************* Stopping Wifi *************");
        ESP_RETURN_ON_ERROR(esp_wifi_stop(), TAG, "Failed to stop WiFi");
        ESP_LOGI(TAG, "************* Setting Wifi mode *************");
        ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "Failed to set WiFi mode");
        ESP_LOGI(TAG, "************* Configuring Wifi *************");
        ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &wifi_config), TAG, "Failed to set WiFi configuration");
        ESP_LOGI(TAG, "************* Starting Wifi *************");
        ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "Failed to start WiFi");

        // esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, wifi_scan_done_handler, NULL);
        wifi_scan_config_t cfg = {
            .ssid      = NULL,
            .bssid     = NULL,
            .channel   = 0,
            .scan_type = WIFI_SCAN_TYPE_ACTIVE,
            .scan_time = {.active = {0, 0}},
        };
        res = esp_wifi_scan_start(&cfg, true);
        if (res != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start scan");
            return res;
        }

        uint16_t num_ap = 0;
        res             = esp_wifi_scan_get_ap_num(&num_ap);
        if (res != ESP_OK) {
            ESP_LOGE(TAG, "Failed to get number of APs");
            return res;
        }

        printf("Found %u APs\r\n", num_ap);

        wifi_ap_record_t* aps = malloc(sizeof(wifi_ap_record_t) * num_ap);
        if (!aps) {
            ESP_LOGE(TAG, "Out of memory (failed to allocate %zd bytes)", sizeof(wifi_ap_record_t) * num_ap);
            num_ap = 0;
            esp_wifi_scan_get_ap_records(&num_ap, NULL);
            return ESP_ERR_NO_MEM;
        }

        res = esp_wifi_scan_get_ap_records(&num_ap, aps);
        if (res != ESP_OK) {
            ESP_LOGE(TAG, "Failed to fetch AP records");
            free(aps);
            return res;
        }

        for (uint16_t i = 0; i < num_ap; i++) {
            wifi_desc_record(&aps[i]);
        }

        if (out_aps) {
            *out_aps        = aps;
            *out_aps_length = num_ap;
        } else {
            free(aps);
        }
    } else {
        printf("WiFi stack not initialized\nThe WiFi stack is not initialized. Please try again later.\n");
        return ESP_ERR_NOT_FOUND;
    }
    return ESP_OK;
}

void app_main(void) {
    // Start the GPIO interrupt service
    gpio_install_isr_service(0);

    // Initialize the Non Volatile Storage service
    esp_err_t res = nvs_flash_init();
    if (res == ESP_ERR_NVS_NO_FREE_PAGES || res == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        res = nvs_flash_init();
    }
    ESP_ERROR_CHECK(res);

    ESP_LOGI(TAG, "************* Before WiFi stack initialize.... *************");
    if (!(wifi_remote_initialize() == ESP_OK)) {
        ESP_LOGE(TAG, "WiFi stack not initialized, cannot scan");
        vTaskDelay(2000 / portTICK_PERIOD_MS);
        return;
    }
    ESP_LOGI(TAG, "WiFi stack initialized, can scan");

    // esp_wifi_scan_start(NULL, true);
    // uint16_t ap_count = 0;
    // wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
    // memset(ap_info, 0, sizeof(ap_info));
    // ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    // ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
    // ESP_LOGI(TAG, "Total APs scanned = %u, actual AP number ap_info holds = %u", ap_count, number);
    // for (int i = 0; i < number; i++) {
    //     ESP_LOGI(TAG, "SSID \t\t%s", ap_info[i].ssid);
    //     ESP_LOGI(TAG, "RSSI \t\t%d", ap_info[i].rssi);
    //     print_auth_mode(ap_info[i].authmode);
    //     if (ap_info[i].authmode != WIFI_AUTH_WEP) {
    //         print_cipher_type(ap_info[i].pairwise_cipher, ap_info[i].group_cipher);
    //     }
    //     ESP_LOGI(TAG, "Channel \t\t%d", ap_info[i].primary);
    // }

    wifi_scan();

    // wifi_ap_record_t* aps     = NULL;
    // uint16_t          num_aps = 0;
    // res     = scan_for_networks(&aps, &num_aps);

    // Initialize the Board Support Package
    ESP_ERROR_CHECK(bsp_device_initialize());
    bsp_led_initialize();

    uint8_t led_data[] = {
        0x47, 0x00, 0xDF, 0x97, 0x5A, 0xEE, 0xD1, 0x4C, 0xE5, 0xCA, 0x68, 0x65, 0x89, 0xEA, 0x14, 0x25, 0xB8, 0x73,
    };
    bsp_led_write(led_data, sizeof(led_data));

    // Get display parameters and rotation
    res = bsp_display_get_parameters(&display_h_res, &display_v_res, &display_color_format, &display_data_endian);
    ESP_ERROR_CHECK(res);  // Check that the display parameters have been initialized
    bsp_display_rotation_t display_rotation = bsp_display_get_default_rotation();

    // Convert ESP-IDF color format into PAX buffer type
    pax_buf_type_t format = PAX_BUF_24_888RGB;
    switch (display_color_format) {
        case LCD_COLOR_PIXEL_FORMAT_RGB565:
            format = PAX_BUF_16_565RGB;
            break;
        case LCD_COLOR_PIXEL_FORMAT_RGB888:
            format = PAX_BUF_24_888RGB;
            break;
        default:
            break;
    }

    // Convert BSP display rotation format into PAX orientation type
    pax_orientation_t orientation = PAX_O_UPRIGHT;
    switch (display_rotation) {
        case BSP_DISPLAY_ROTATION_90:
            orientation = PAX_O_ROT_CCW;
            break;
        case BSP_DISPLAY_ROTATION_180:
            orientation = PAX_O_ROT_HALF;
            break;
        case BSP_DISPLAY_ROTATION_270:
            orientation = PAX_O_ROT_CW;
            break;
        case BSP_DISPLAY_ROTATION_0:
        default:
            orientation = PAX_O_UPRIGHT;
            break;
    }

        // Initialize graphics stack
#if defined(CONFIG_BSP_TARGET_KAMI)
    format = PAX_BUF_2_PAL;
#endif

    pax_buf_init(&fb, NULL, display_h_res, display_v_res, format);
    pax_buf_reversed(&fb, display_data_endian == LCD_RGB_DATA_ENDIAN_BIG);

#if defined(CONFIG_BSP_TARGET_KAMI)
    fb.palette      = palette;
    fb.palette_size = sizeof(palette) / sizeof(pax_col_t);
#endif

#if defined(CONFIG_BSP_TARGET_KAMI)
#define BLACK 0
#define WHITE 1
#define RED   2
#else
#define BLACK 0xFF000000
#define WHITE 0xFFFFFFFF
#define RED   0xFFFF0000
#endif

    pax_buf_set_orientation(&fb, orientation);

    // Get input event queue from BSP
    ESP_ERROR_CHECK(bsp_input_get_queue(&input_event_queue));

    ESP_LOGW(TAG, "Hello world!");

    pax_background(&fb, WHITE);
    pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 0, "Hello world!");
    blit();

    while (1) {
        bsp_input_event_t event;
        if (xQueueReceive(input_event_queue, &event, portMAX_DELAY) == pdTRUE) {
            switch (event.type) {
                case INPUT_EVENT_TYPE_KEYBOARD: {
                    if (event.args_keyboard.ascii != '\b' ||
                        event.args_keyboard.ascii != '\t') {  // Ignore backspace & tab keyboard events
                        ESP_LOGI(TAG, "Keyboard event %c (%02x) %s", event.args_keyboard.ascii,
                                 (uint8_t)event.args_keyboard.ascii, event.args_keyboard.utf8);
                        pax_simple_rect(&fb, WHITE, 0, 0, pax_buf_get_width(&fb), 72);
                        pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 0, "Keyboard event");
                        char text[64];
                        snprintf(text, sizeof(text), "ASCII:     %c (0x%02x)", event.args_keyboard.ascii,
                                 (uint8_t)event.args_keyboard.ascii);
                        pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 18, text);
                        snprintf(text, sizeof(text), "UTF-8:     %s", event.args_keyboard.utf8);
                        pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 36, text);
                        snprintf(text, sizeof(text), "Modifiers: 0x%0" PRIX32, event.args_keyboard.modifiers);
                        pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 54, text);
                        blit();
                    }
                    break;
                }
                case INPUT_EVENT_TYPE_NAVIGATION: {
                    ESP_LOGI(TAG, "Navigation event %0" PRIX32 ": %s", (uint32_t)event.args_navigation.key,
                             event.args_navigation.state ? "pressed" : "released");

                    if (event.args_navigation.key == BSP_INPUT_NAVIGATION_KEY_F1) {
                        bsp_device_restart_to_launcher();
                    }
                    if (event.args_navigation.key == BSP_INPUT_NAVIGATION_KEY_F2) {
                        bsp_input_set_backlight_brightness(0);
                    }
                    if (event.args_navigation.key == BSP_INPUT_NAVIGATION_KEY_F3) {
                        bsp_input_set_backlight_brightness(100);
                    }

                    pax_simple_rect(&fb, WHITE, 0, 100, pax_buf_get_width(&fb), 72);
                    pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 100 + 0, "Navigation event");
                    char text[64];
                    snprintf(text, sizeof(text), "Key:       0x%0" PRIX32, (uint32_t)event.args_navigation.key);
                    pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 100 + 18, text);
                    snprintf(text, sizeof(text), "State:     %s", event.args_navigation.state ? "pressed" : "released");
                    pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 100 + 36, text);
                    snprintf(text, sizeof(text), "Modifiers: 0x%0" PRIX32, event.args_navigation.modifiers);
                    pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 100 + 54, text);
                    blit();
                    break;
                }
                case INPUT_EVENT_TYPE_ACTION: {
                    ESP_LOGI(TAG, "Action event 0x%0" PRIX32 ": %s", (uint32_t)event.args_action.type,
                             event.args_action.state ? "yes" : "no");
                    pax_simple_rect(&fb, WHITE, 0, 200 + 0, pax_buf_get_width(&fb), 72);
                    pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 200 + 0, "Action event");
                    char text[64];
                    snprintf(text, sizeof(text), "Type:      0x%0" PRIX32, (uint32_t)event.args_action.type);
                    pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 200 + 36, text);
                    snprintf(text, sizeof(text), "State:     %s", event.args_action.state ? "yes" : "no");
                    pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 200 + 54, text);
                    blit();
                    break;
                }
                case INPUT_EVENT_TYPE_SCANCODE: {
                    ESP_LOGI(TAG, "Scancode event 0x%0" PRIX32, (uint32_t)event.args_scancode.scancode);
                    pax_simple_rect(&fb, WHITE, 0, 300 + 0, pax_buf_get_width(&fb), 72);
                    pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 300 + 0, "Scancode event");
                    char text[64];
                    snprintf(text, sizeof(text), "Scancode:  0x%0" PRIX32, (uint32_t)event.args_scancode.scancode);
                    pax_draw_text(&fb, BLACK, pax_font_sky_mono, 16, 0, 300 + 36, text);
                    blit();
                    break;
                }
                default:
                    break;
            }
        }
    }
}
