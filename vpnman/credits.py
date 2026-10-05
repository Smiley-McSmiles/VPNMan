"""Attribution and donation details shown in the About dialog, the CLI and the README."""

from . import __version__

DEVELOPER_NAME = "WOOSAH"
DEVELOPERS = ["WOOSAH (Lead Architect)", "Claude (Engineer)"]
COPYRIGHT = "\u00a9 2026 WOOSAH & Claude"
COPYRIGHT_MARKUP = COPYRIGHT.replace("&", "&amp;")   # the About dialog parses it as Pango markup
COMMENTS = ("Multi-protocol VPN manager with a modern GTK4 / Libadwaita desktop GUI, an interactive terminal CLI "
            "and a built-in network lock (kill switch).")
WEBSITE = "https://github.com/Smiley-McSmiles/VPNMan"
ISSUE_URL = WEBSITE + "/issues"
SUPPORT_URL = WEBSITE

# The title of the row in the About dialog; it opens a sub-page (like Credits / Legal) listing the options below.
# Each option is (button title, text copied to the user's clipboard when pressed).
DONATION_BUTTON_LABEL = "Donate"
DONATION_PAGE_TITLE = "Donate"
DONATION_OPTIONS = [
    ('BTC', 'bc1qy2gtdhnfxp9dcs6v9jda748npmsjx3jgwp99mx'),
    ('XMR', '82xtMVSmesuLjPtgHfBCEhM5Fpqh1SLLNf9pzHRRNPqQZsvrnmoM1ZGC7AiLyPfsufdyrMWHrWYV2hsC8jc5rEBVLMHWTLy'),
    ('CashApp', '$SmileyMcSmiles'),
]


def about_text():
    lines = ["VPNMan %s" % __version__, COMMENTS, "", "Developers:"]
    lines += ["  - %s" % d for d in DEVELOPERS]
    lines += ["", COPYRIGHT, WEBSITE, "", "Donate (copy the text):"]
    lines += ["  %-8s %s" % (k, v) for k, v in DONATION_OPTIONS]
    return "\n".join(lines)
