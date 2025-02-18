/*******************************************************************************
 *   (c) 2018 - 2024 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "bolos_target.h"

#if defined(TARGET_STAX) || defined(TARGET_FLEX)

#include "actions.h"
#include "app_mode.h"
#include "nbgl_page.h"
#include "nbgl_use_case.h"
#include "ux.h"
#include "view_internal.h"
#include "menu_handler.h"

#ifdef APP_SECRET_MODE_ENABLED
zxerr_t secret_enabled();
#endif

#ifdef APP_ACCOUNT_MODE_ENABLED
zxerr_t account_enabled();
#endif

#define APPROVE_LABEL_NBGL "Sign transaction?"
#define APPROVE_LABEL_NBGL_GENERIC "Accept operation?"
#define CANCEL_LABEL "Cancel"
#define VERIFY_TITLE_LABEL_GENERIC "Verify operation"
#define INFO_LIST_SIZE 2
#define SETTING_CONTENTS_NB 1
static const char HOME_TEXT[] =
    "This application enables\nsigning transactions on the\n" MENU_MAIN_APP_LINE1 " network";

static const char ADDRESS_TEXT[] = "Verify " MENU_MAIN_APP_LINE1 "\naddress";

ux_state_t G_ux;
bolos_ux_params_t G_ux_params;
extern unsigned int review_type;

const char *intro_message = NULL;

static nbgl_layoutTagValue_t pairs[NB_MAX_DISPLAYED_PAIRS_IN_REVIEW];

static nbgl_layoutTagValue_t pair;
static nbgl_layoutTagValueList_t pairList;

static nbgl_layoutTagValueList_t *extraPagesPtr = NULL;

typedef enum {
    EXPERT_MODE = 0,
#ifdef APP_ACCOUNT_MODE_ENABLED
    ACCOUNT_MODE,
#endif
#ifdef APP_SECRET_MODE_ENABLED
    SECRET_MODE,
#endif
#ifdef APP_BLINDSIGN_MODE_ENABLED
    BLINDSIGN_MODE,
#endif
    SETTINGS_SWITCHES_NB_LEN
} settings_list_e;

typedef enum {
    EXPERT_MODE_TOKEN = FIRST_USER_TOKEN,
    ACCOUNT_MODE_TOKEN,
    SECRET_MODE_TOKEN,
    BLINDSIGN_MODE_TOKEN,
} config_token_e;

void app_quit(void) {
    // exit app here
    os_sched_exit(-1);
}

static void h_reject_internal(void) { h_reject(review_type); }

static void h_approve_internal(void) { h_approve(review_type); }

static void h_view_address(void);

#ifdef TARGET_STAX
#define MAX_INFO_LIST_ITEM_PER_PAGE 3
#else  // TARGET_FLEX
#define MAX_INFO_LIST_ITEM_PER_PAGE 2
#endif

static const char *const INFO_KEYS_PAGE[] = {"Version", "License"};
static const char *const INFO_VALUES_PAGE[] = {APPVERSION, "Apache 2.0"};

static const char SHOW_STORED_PUBKEY_TEXT[] = "Show address";

static nbgl_contentInfoList_t infoList = {0};
static nbgl_genericContents_t settingContents = {0};
static nbgl_homeAction_t showStoredPubkey = {};
static nbgl_contentSwitch_t switches[SETTINGS_SWITCHES_NB_LEN];

static void h_expert_toggle() { app_mode_set_expert(!app_mode_expert()); }

#ifdef APP_BLINDSIGN_MODE_ENABLED
static void h_blindsign_toggle() { app_mode_set_blindsign(!app_mode_blindsign()); }
#endif

static void confirm_error(__Z_UNUSED bool confirm) { h_error_accept(0); }

static void reviewAddressChoice(bool confirm) {
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, h_approve_internal);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, h_reject_internal);
    }
}

static void reviewTransactionChoice(bool confirm) {
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, h_approve_internal);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, h_reject_internal);
    }
}

static void reviewGenericChoice(bool confirm) {
    const char *msg = "Operation rejected";
    bool isSuccess = false;

    if (confirm) {
        msg = "Operation approved";
        isSuccess = true;
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, h_approve_internal);
    }

    nbgl_useCaseStatus(msg, isSuccess, confirm ? h_approve_internal : h_reject_internal);
}

static void confirm_setting(bool confirm) {
    if (confirm && viewdata.viewfuncAccept != NULL) {
        viewdata.viewfuncAccept();
        return;
    }

    h_reject_internal();
}

void view_error_show() {
    viewdata.key = viewdata.keys[0];
    viewdata.value = viewdata.values[0];
    MEMZERO(viewdata.key, MAX_CHARS_PER_KEY_LINE);
    MEMZERO(viewdata.value, MAX_CHARS_PER_VALUE1_LINE);
    snprintf(viewdata.key, MAX_CHARS_PER_KEY_LINE, "ERROR");
    snprintf(viewdata.value, MAX_CHARS_PER_VALUE1_LINE, "SHOWING DATA");
    view_error_show_impl();
}

void view_custom_error_show(const char *upper, const char *lower) {
    viewdata.key = viewdata.keys[0];
    viewdata.value = viewdata.values[0];
    MEMZERO(viewdata.key, MAX_CHARS_PER_KEY_LINE);
    MEMZERO(viewdata.value, MAX_CHARS_PER_VALUE1_LINE);
    snprintf(viewdata.key, MAX_CHARS_PER_KEY_LINE, "%s", upper);
    snprintf(viewdata.value, MAX_CHARS_PER_VALUE1_LINE, "%s", lower);

    nbgl_useCaseChoice(&C_Important_Circle_64px, viewdata.key, viewdata.value, "Ok", "", confirm_error);
}

void view_blindsign_error_show() {
    nbgl_useCaseChoice(&C_Warning_64px, "This message cannot\nbe clear-signed",
                       "Enable blind-signing in\nthe settings to sign\nthis transaction.", "Exit", "", confirm_error);
}

void view_error_show_impl() {
    nbgl_useCaseChoice(&C_Important_Circle_64px, viewdata.key, viewdata.value, "Ok", NULL, confirm_setting);
}

static uint8_t get_pair_number() {
    uint8_t numItems = 0;
    uint8_t numPairs = 0;
    viewdata.viewfuncGetNumItems(&numItems);
    for (uint8_t i = 0; i < numItems; i++) {
        viewdata.viewfuncGetItem(i, viewdata.key, MAX_CHARS_PER_KEY_LINE, viewdata.value, MAX_CHARS_PER_VALUE1_LINE, 0,
                                 &viewdata.pageCount);
        numPairs += viewdata.pageCount;
    }
    return numPairs;
}

zxerr_t h_review_update_data() {
    if (viewdata.viewfuncGetNumItems == NULL) {
        ZEMU_LOGF(50, "h_review_update_data - GetNumItems == NULL\n")
        return zxerr_no_data;
    }
    if (viewdata.viewfuncGetItem == NULL) {
        ZEMU_LOGF(50, "h_review_update_data - GetItems == NULL\n")
        return zxerr_no_data;
    }

    if (viewdata.viewfuncAccept == NULL) {
        ZEMU_LOGF(50, "h_review_update_data - Function Accept == NULL\n")
        return zxerr_no_data;
    }

    if (viewdata.key == NULL || viewdata.value == NULL) {
        return zxerr_unknown;
    }

    CHECK_ZXERR(viewdata.viewfuncGetNumItems(&viewdata.itemCount))

    uint8_t accPages = 0;
    for (uint8_t i = 0; i < viewdata.itemCount; i++) {
        CHECK_ZXERR(viewdata.viewfuncGetItem(i, viewdata.key, MAX_CHARS_PER_KEY_LINE, viewdata.value,
                                             MAX_CHARS_PER_VALUE1_LINE, 0, &viewdata.pageCount))
        if (viewdata.pageCount == 0) {
            ZEMU_LOGF(50, "pageCount is 0!")
            return zxerr_no_data;
        }

        if (accPages + viewdata.pageCount > viewdata.itemIdx) {
            const uint8_t innerIdx = viewdata.itemIdx - accPages;
            CHECK_ZXERR(viewdata.viewfuncGetItem(i, viewdata.key, MAX_CHARS_PER_KEY_LINE, viewdata.value,
                                                 MAX_CHARS_PER_VALUE1_LINE, innerIdx, &viewdata.pageCount))
            if (viewdata.pageCount > 1) {
                const uint8_t titleLen = strnlen(viewdata.key, MAX_CHARS_PER_KEY_LINE);
                snprintf(viewdata.key + titleLen, MAX_CHARS_PER_KEY_LINE - titleLen, " (%d/%d)", innerIdx + 1,
                         viewdata.pageCount);
            }
            return zxerr_ok;
        }
        accPages += viewdata.pageCount;
    }

    return zxerr_no_data;
}

void h_review_update() {
    zxerr_t err = h_review_update_data();
    switch (err) {
        case zxerr_ok:
        case zxerr_no_data:
            break;
        default:
            ZEMU_LOGF(50, "View error show\n")
            view_error_show();
            break;
    }
}

void settings_toggle_callback(int token, uint8_t index, int page) {
    UNUSED(index);
    UNUSED(page);

    switch (token) {
        case EXPERT_MODE_TOKEN:
            h_expert_toggle();
            break;

#ifdef APP_ACCOUNT_MODE_ENABLED
        case ACCOUNT_MODE_TOKEN:
            account_enabled();
            break;
#endif

#ifdef APP_SECRET_MODE_ENABLED
        case SECRET_MODE_TOKEN:
            secret_enabled();
            break;
#endif

#ifdef APP_BLINDSIGN_MODE_ENABLED
        case BLINDSIGN_MODE_TOKEN:
            h_blindsign_toggle();
            break;
#endif

        default:
            ZEMU_LOGF(50, "Toggling setting not found\n")
            break;
    }
}

static void settings_screen_callback(uint8_t index, nbgl_content_t *content) {
    UNUSED(index);
    switches[EXPERT_MODE].initState = app_mode_expert();
    switches[EXPERT_MODE].text = "Expert mode";
    switches[EXPERT_MODE].subText = "";
    switches[EXPERT_MODE].tuneId = TUNE_TAP_CASUAL;
    switches[EXPERT_MODE].token = EXPERT_MODE_TOKEN;

#ifdef APP_BLINDSIGN_MODE_ENABLED
    switches[BLINDSIGN_MODE].initState = app_mode_blindsign();
    switches[BLINDSIGN_MODE].text = "Blind sign";
    switches[BLINDSIGN_MODE].subText = "";
    switches[BLINDSIGN_MODE].tuneId = TUNE_TAP_CASUAL;
    switches[BLINDSIGN_MODE].token = BLINDSIGN_MODE_TOKEN;
#endif

#ifdef APP_ACCOUNT_MODE_ENABLED
    if (app_mode_expert() || app_mode_account()) {
        switches[ACCOUNT_MODE].initState = app_mode_account();
        switches[ACCOUNT_MODE].text = "Crowdloan account";
        switches[ACCOUNT_MODE].subText = "";
        switches[ACCOUNT_MODE].tuneId = TUNE_TAP_CASUAL;
        switches[ACCOUNT_MODE].token = ACCOUNT_MODE_TOKEN;
    }
#endif

#ifdef APP_SECRET_MODE_ENABLED
    if (app_mode_expert() || app_mode_secret()) {
        switches[SECRET_MODE].initState = app_mode_secret();
        switches[SECRET_MODE].text = "Secret mode";
        switches[SECRET_MODE].subText = "";
        switches[SECRET_MODE].tuneId = TUNE_TAP_CASUAL;
        switches[SECRET_MODE].token = SECRET_MODE_TOKEN;
    }
#endif

    content->type = SWITCHES_LIST;
    content->content.switchesList.nbSwitches = SETTINGS_SWITCHES_NB_LEN;
    content->content.switchesList.switches = switches;
    content->contentActionCallback = settings_toggle_callback;
}

void view_idle_show_impl(__Z_UNUSED uint8_t item_idx, const char *statusString) {
    viewdata.key = viewdata.keys[0];
    const char *home_text = HOME_TEXT;
    if (statusString == NULL) {
#ifdef APP_SECRET_MODE_ENABLED
        if (app_mode_secret()) {
            snprintf(viewdata.key, MAX_CHARS_PER_KEY_LINE, "%s", MENU_MAIN_APP_LINE2_SECRET);
            home_text = viewdata.key;
        }
#endif
    } else {
        snprintf(viewdata.key, MAX_CHARS_PER_KEY_LINE, "%s", statusString);
    }

    settingContents.callbackCallNeeded = true;
    settingContents.nbContents = SETTING_CONTENTS_NB;
    settingContents.contentGetterCallback = settings_screen_callback;

    infoList.nbInfos = INFO_LIST_SIZE;
    infoList.infoContents = INFO_VALUES_PAGE;
    infoList.infoTypes = INFO_KEYS_PAGE;

    showStoredPubkey.text = SHOW_STORED_PUBKEY_TEXT;
    showStoredPubkey.icon = NULL;
    showStoredPubkey.callback =  h_view_address;
    showStoredPubkey.style = SOFT_HOME_ACTION;

    nbgl_useCaseHomeAndSettings(MENU_MAIN_APP_LINE1, &C_icon_stax_64, home_text, INIT_HOME_PAGE, &settingContents,
                                &infoList, &showStoredPubkey, app_quit);
}

void view_message_impl(const char *title, const char *message) {
    viewdata.value = viewdata.values[0];
    uint32_t titleLen = 0;
    if (title != NULL) {
        snprintf(viewdata.value, MAX_CHARS_PER_VALUE1_LINE, "%s", title);
        titleLen = strnlen(title, MAX_CHARS_PER_VALUE1_LINE);
    }

    if (message != NULL) {
        const char sep = (titleLen > 0) ? 0x0A : 0x00;
        snprintf(viewdata.value, MAX_CHARS_PER_VALUE1_LINE - titleLen, "%c%s", sep, message);
    }

    nbgl_useCaseSpinner(viewdata.value);
}

static void review_configuration() {
    viewdata.key = viewdata.keys[0];
    viewdata.value = viewdata.values[0];
    const zxerr_t err = h_review_update_data();
    if (err != zxerr_ok) {
        ZEMU_LOGF(50, "Config screen error\n")
        view_error_show();
    }

    nbgl_useCaseChoice(&C_Important_Circle_64px, viewdata.key, viewdata.value, "Accept", "Reject", confirm_setting);
}

static void config_useCaseAddressReview() {
    extraPagesPtr = NULL;
    uint8_t numItems = 0;
    if (viewdata.viewfuncGetNumItems == NULL || viewdata.viewfuncGetNumItems(&numItems) != zxerr_ok ||
        numItems > NB_MAX_DISPLAYED_PAIRS_IN_REVIEW) {
        ZEMU_LOGF(50, "Show address error\n")
        view_error_show();
    }

    for (uint8_t idx = 1; idx < numItems; idx++) {
        pairs[idx - 1].item = viewdata.keys[idx];
        pairs[idx - 1].value = viewdata.values[idx];

        viewdata.itemIdx = idx;
        viewdata.key = viewdata.keys[idx];
        viewdata.value = viewdata.values[idx];
        h_review_update_data();

        pairList.nbMaxLinesForValue = 0;
        pairList.nbPairs = idx;
        pairList.pairs = pairs;
        extraPagesPtr = &pairList;
    }

    viewdata.itemIdx = 0;
    viewdata.key = viewdata.keys[0];
    viewdata.value = viewdata.values[0];
    h_review_update_data();

#if defined(CUSTOM_ADDRESS_TEXT)
    UNUSED(ADDRESS_TEXT);
    intro_message = CUSTOM_ADDRESS_TEXT;
#else
    intro_message = ADDRESS_TEXT;
#endif
    nbgl_useCaseAddressReview(viewdata.value, extraPagesPtr, &C_icon_stax_64, intro_message, NULL, reviewAddressChoice);
}

static nbgl_layoutTagValue_t *update_item_callback(uint8_t index) {
    uint8_t internalIndex = index % NB_MAX_DISPLAYED_PAIRS_IN_REVIEW;

    viewdata.itemIdx = index;
    viewdata.key = viewdata.keys[internalIndex];
    viewdata.value = viewdata.values[internalIndex];

    h_review_update_data();
    pair.item = viewdata.key;
    pair.value = viewdata.value;
    return &pair;
}

static void config_useCaseReview(nbgl_operationType_t type) {
    if (viewdata.viewfuncGetNumItems == NULL) {
        ZEMU_LOGF(50, "GetNumItems==NULL\n")
        view_error_show();
        return;
    }

    pairList.nbMaxLinesForValue = NB_MAX_LINES_IN_REVIEW;
    pairList.nbPairs = get_pair_number();
    pairList.pairs = NULL;  // to indicate that callback should be used
    pairList.callback = update_item_callback;
    pairList.startIndex = 0;
    if (app_mode_blindsign_required()) {
        nbgl_useCaseReviewBlindSigning(type, &pairList, &C_icon_stax_64,
                                       (intro_message == NULL ? "Review transaction" : intro_message), NULL,
                                       "Accept risk and sign transaction ?", NULL, reviewTransactionChoice);
    } else {
        nbgl_useCaseReview(type, &pairList, &C_icon_stax_64,
                           (intro_message == NULL ? "Review transaction" : intro_message), NULL, APPROVE_LABEL_NBGL,
                           reviewTransactionChoice);
    }
}

static void config_useCaseReviewLight(const char *title, const char *validate) {
    if (viewdata.viewfuncGetNumItems == NULL) {
        ZEMU_LOGF(50, "GetNumItems==NULL\n")
        view_error_show();
        return;
    }

    pairList.nbMaxLinesForValue = NB_MAX_LINES_IN_REVIEW;
    pairList.nbPairs = get_pair_number();
    pairList.pairs = NULL;  // to indicate that callback should be used
    pairList.callback = update_item_callback;
    pairList.startIndex = 0;

    nbgl_useCaseReviewLight(TYPE_OPERATION, &pairList, &C_icon_stax_64,
                            (title == NULL ? VERIFY_TITLE_LABEL_GENERIC : title), NULL,
                            (validate == NULL ? APPROVE_LABEL_NBGL_GENERIC : validate), reviewGenericChoice);
}

void view_review_show_impl(unsigned int requireReply, const char *title, const char *validate) {
    review_type = (review_type_e)requireReply;

    // Retrieve intro text for transaction
    intro_message = NULL;
    viewdata.key = viewdata.keys[0];
    viewdata.value = viewdata.values[0];
    if (viewdata.viewfuncGetItem != NULL) {
        const zxerr_t err = viewdata.viewfuncGetItem(0xFF, viewdata.key, MAX_CHARS_PER_KEY_LINE, viewdata.value,
                                                     MAX_CHARS_PER_VALUE1_LINE, 0, &viewdata.pageCount);
        if (err == zxerr_ok) {
            intro_message = viewdata.value;
        }
    }
    h_paging_init();

    switch (review_type) {
        case REVIEW_UI:
            nbgl_useCaseReviewStart(&C_icon_stax_64, "Review configuration", NULL, CANCEL_LABEL, review_configuration,
                                    h_reject_internal);
            break;
        case REVIEW_ADDRESS: {
            config_useCaseAddressReview();
            break;
        }
        case REVIEW_GENERIC: {
            config_useCaseReviewLight(title, validate);
            break;
        }
        case REVIEW_TXN:
        default:
            config_useCaseReview(TYPE_TRANSACTION);
            break;
    }
}

static void h_view_address() {
    handleMenuShowAddress();
}

#endif
