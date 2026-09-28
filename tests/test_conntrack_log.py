from deploy.pivpn_webui_conntrack_log import normalize


def test_normalizes_conntrack_new_event_to_flow_line():
    line = (
        "[1790587341.484159] [NEW] ipv4 2 tcp 6 120 SYN_SENT "
        "src=10.8.0.2 dst=64.233.170.108 sport=58719 dport=993 [UNREPLIED] "
        "src=64.233.170.108 dst=172.17.134.51 sport=993 dport=58719"
    )

    assert normalize(line) == (
        "VPNFLOW IN= OUT= SRC=10.8.0.2 DST=64.233.170.108 PROTO=TCP "
        "SPT=58719 DPT=993 HOST_REALTIME_US=1790587341484159"
    )


def test_ignores_non_new_and_malformed_events():
    assert normalize("[1790587341.4] [UPDATE] ipv4 2 tcp 6 src=10.8.0.2") is None
    assert normalize("not a conntrack event") is None
