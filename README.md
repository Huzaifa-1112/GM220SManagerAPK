# GM220-S Manager

Android app for the GM220-S web management interface.

## Current features

- Login to `192.168.1.1` (or another modem LAN IP)
- Read the GM220-S DHCP/client table
- Show MAC, IP, host name and port/PHY type
- Read the MAC-filter list
- Block a device by adding its MAC to MAC Filter / Discard
- Unblock a device by deleting its MAC-filter rule
- Refresh the device list

## Important

This project was built against the GM220-S traffic capture supplied in the chat. The capture showed:

- Login: `POST /`
- Token refresh: `GET /keepAlive.gch`
- DHCP/client page: `/getpage.gch?pid=1002&nextpage=net_dhcp_dynamic_t.gch`
- MAC filter page: `/getpage.gch?pid=1002&nextpage=sec_macfilter_conf_t.gch`
- MAC filter add: `IF_ACTION=new`
- MAC filter delete: `IF_ACTION=delete`

The app does not contain your modem password or captured session token. Enter your own credentials at runtime.

## Build on Android

Acode is useful for editing, but it does not normally compile a full Android Gradle project by itself. On a phone, use an Android Gradle IDE such as AndroidIDE (if available for your device), import this project, then Build APK.

Alternatively open this project in Android Studio on a computer.

## First test

1. Connect the phone to the GM220-S Wi-Fi.
2. Open the app.
3. Enter modem IP, username and password.
4. Tap LOGIN.
5. Confirm the DHCP devices appear.
6. Test BLOCK on a non-critical test device.
7. Test UNBLOCK.

Do not block the phone you are using to manage the modem unless you are prepared to reconnect from another device.

## Security

The GM220-S interface in the supplied capture uses plain HTTP on the LAN. The app therefore uses cleartext HTTP. Use this only on a trusted local network.

The supplied PCAP contained login information. Change the modem's admin password after testing the capture.
