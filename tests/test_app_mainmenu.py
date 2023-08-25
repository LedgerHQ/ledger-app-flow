from ragger.navigator import NavInsID

from utils import ROOT_SCREENSHOT_PATH


def test_app_mainmenu(firmware, navigator, test_name):
    """ Check the behavior of the device main menu """

    # Navigate in the main menu and check screens
    if firmware.device.startswith("nano"):
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.LEFT_CLICK,
            NavInsID.LEFT_CLICK,
            NavInsID.LEFT_CLICK,
            NavInsID.LEFT_CLICK,
            NavInsID.LEFT_CLICK,
        ]
    else:
        instructions = [
            NavInsID.USE_CASE_HOME_INFO,
            NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT
        ]
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions,
                                   screen_change_before_first_instruction=False)
