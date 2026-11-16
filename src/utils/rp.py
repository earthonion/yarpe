from constants import FONT_PATH, rp, CONFIG

__all__ = ["log", "log_exc"]

debug_log = []
exception_occurred = False


def delete_last_line(event, interact=True, **kwargs):
    global debug_log
    global exception_occurred
    if len(debug_log) > 0 and exception_occurred and interact and event == "end":
        exception_occurred = False
        debug_log.pop()


debug_char = rp.store.Character(
    None,
    callback=delete_last_line,
    what_color=CONFIG.get("color", "#42f2f5"),
    what_size=18,
    what_font=FONT_PATH,
    what_xalign=0.0,
    what_yalign=0.0,
    what_outlines=[(2, "#000000", 0, 0)],
    what_background=rp.store.Solid("#000000"),
    ctc=None,
    ctc_pause=None,
    ctc_timedpause=None,
    what_slow_cps=0,
    window_background=rp.store.Solid("#000000"),
    window_xfill=True,
    window_yfill=True,
    window_xalign=0.0,
    window_yalign=0.0,
    window_left_padding=20,
    window_top_padding=20,
    window_left_margin=0,
    window_right_margin=0,
    window_top_margin=0,
    window_bottom_margin=0,
)


payload_log = []


def log(*args):
    global debug_log
    msg = " ".join([str(arg) for arg in list(args)])
    wait = False
    if rp.config.name == "One Night Stand":
        wait = msg.endswith("{w}")
        display_msg = msg[:-3] if wait else msg
        # escape brackets to avoid built-in renpy exceptions
        strings = display_msg.replace("[", "[[").replace("{", "{{").split("\n")
    else:
        strings = msg.split("\n")
    debug_log.extend(strings)
    if len(debug_log) > 32:
        debug_log = debug_log[-32:]
    full_msg = "{nw}" + "\n".join(debug_log)
    if wait:
        full_msg += "{w}"
    rp.game.invoke_in_new_context(debug_char, full_msg)

    from constants import SHARED_VARS
    if SHARED_VARS.get("client_sock") is not None:
        payload_log.append(msg + "\n")


def log_exc(string):
    global exception_occurred
    if rp.config.name == "One Night Stand":
        log("EXCEPTION: " + string)
    else:
        log("{b}[EXCEPTION] " + string + "{/b}")
    exception_occurred = True
    log("An error occurred! Press X(or O) to continue.{w}")
