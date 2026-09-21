# FindMy - Home Assistant integration

Experimental custom integration to provide device tracker entities for FindMy Network-enabled devices.

## Setting up

1. Add this repository to HACS and install the `FindMy` integration.
2. Enable the integration. You must add at least two 'devices': one Apple Account and one tracker device.
   1. When adding an account, you will need to specify an anisette server. You can use a public one, but it
      might start throwing errors after a while, so private servers are preferred. Google is your friend.
3. Enjoy!

## Increasing the update frequency

By default, the integration will only use your account to fetch for updates once per 15 minutes. This is to
reduce the risk of being banned by Apple. If you want to increase the tracker update frequency, it is possible
to add additional accounts. These accounts will divide the available time; 2 accounts will generate updates every
7.5 minutes, 3 will update every 5 minutes, etc.

## Local Bluetooth tracking

Rolling-key accessories such as official AirTags can also be detected by Home Assistant Bluetooth adapters and
ESPHome Bluetooth proxies. Local detections update independently of the 15-minute Find My network polling interval.

The device tracker exposes the confirmed current address in `mac_address` and adds these attributes:

- `local_detected_at`
- `local_rssi`
- `local_source`
- `local_state` (`nearby` or `separated`)
- `local_battery` (`Full`, `Medium`, `Low`, or `Very Low`)
- `local_key_candidates`

All key matching happens inside Home Assistant. Local presence tracking therefore continues without an internet
connection after the rolling-key accessory has been imported, although remote Find My network locations still
require an Apple account and internet access.
