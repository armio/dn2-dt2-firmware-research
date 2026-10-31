/* Private DT2-compatible state. Native ProjectSettings has different fields. */
.text
.global restore_proxy_raw
restore_proxy_raw:
 movea.l 4(%sp),%a0
 move.l 0xac(%a0),4(%sp)
 jmp settings_raw
