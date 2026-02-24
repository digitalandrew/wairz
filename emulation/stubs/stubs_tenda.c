/*
 * stubs_tenda.c — Tenda-specific LD_PRELOAD stubs for firmware emulation.
 *
 * Simple return-value stubs for Tenda-proprietary functions that fail
 * under QEMU due to missing hardware drivers (WiFi, I/O framework,
 * process monitor). Use together with stubs_generic.so.
 *
 * Build (cross-compile, e.g. for mipsel):
 *   mipsel-linux-gnu-gcc -nostdlib -fPIC -shared -Wl,--hash-style=sysv \
 *       -o stubs_tenda_mipsel.so stubs_tenda.c
 */

/* ifaddrs_get_lan_ifname(void) → char *
 * Returns the LAN bridge interface name. Original calls iof_eth_name_get(0)
 * from libiofdrv.so which doesn't work under QEMU. */
static char _lan_ifname[] = "br0";
char *ifaddrs_get_lan_ifname(void)
{
    return _lan_ifname;
}

/* GetConutryCode(void) → int
 * Reads WiFi country code via wireless ioctls. Returns 0 (success). */
int GetConutryCode(void)
{
    return 0;
}

/* tpi_wifi_get_channel_list_by_country(void) → int
 * Retrieves WiFi channel list for a country. Returns 0 (success, empty list). */
int tpi_wifi_get_channel_list_by_country(void)
{
    return 0;
}

/* proc_check_app(const char *name) → int
 * Checks if a process is running by scanning /proc. Returns 1 (found). */
int proc_check_app(const char *name)
{
    (void)name;
    return 1;
}

/* monitor_system_network_ok(void) → int
 * Checks network readiness via process monitor. Returns 1 (OK). */
int monitor_system_network_ok(void)
{
    return 1;
}

/* ugw_proc_send_msg(int *msg, int socket_path) → long
 * Sends a message via UNIX socket. Returns msg[0]+4 (bytes "sent"). */
long ugw_proc_send_msg(int *msg, int socket_path)
{
    (void)socket_path;
    if (!msg)
        return -1;
    return msg[0] + 4;
}
