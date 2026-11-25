# FindMy - Home Assistant integration

Experimental custom integration to provide device tracker entities for FindMy Network-enabled devices.

## Setting up

### Installing

This integration is not yet in the HACS default store, so add it as a custom repository:

1. In HACS, open the three-dot menu → **Custom repositories**.
2. Paste `https://github.com/malmeloo/hass-FindMy`, choose the **Integration** category, and click **Add**.
3. Find **FindMy** in the list, open it and click **Download**.
4. **Restart Home Assistant.** This is required so the `findmy` Python dependency is installed; without
   the restart the config flow fails to load with `No module named 'findmy'`.
5. Go to **Settings → Devices & services → Add integration** and search for **FindMy**.

> HACS may log an error about a failed zip download the first time. This is harmless — HACS falls back to
> cloning the repository.

### Adding accounts and devices

Add entries one at a time. You need at least one Apple Account entry and one device entry.

- **Apple Account:** sign in with your Apple ID. You can optionally set a remote anisette server under
  *Advanced options*. Public servers work but can become unreliable, so a self-hosted one is preferred.
- **Device:** choose the device type and provide its keys (see below).

### Getting your device keys

A tracker entry needs the device's keys. How you obtain them depends on the device:

- **AirTags and other official Find My accessories:** export the keys on a Mac that is signed in to the
  Apple ID the tags are registered to. Community tools that do this:
  - [OpenTagViewer](https://github.com/parawanderer/OpenTagViewer) — exports per-tag `.plist` files (look in
    the `OwnedBeacons` subfolders). Upload one as a **rolling-key device with derived keys**.
  - [export-findmy](https://github.com/stek29/export-findmy) — reported working on recent macOS.
  - [FindMy.py's own guide](https://docs.mikealmel.ooo/FindMy.py/getstarted/02-fetching.html), which
    documents `python3 -m findmy decrypt` and the per-macOS-version steps.

  Key extraction is most reliable on macOS 14; newer macOS protects the store key and may need extra steps.
  The first network fetch for a freshly imported tag can take a while, because alignment data is not
  exported — a nearby Bluetooth scan speeds it up.
- **Custom OpenHaystack / macless-haystack tags:** add them as a **static-key device** with the private
  key in base64. If you don't have one yet, `KeyPair.new()` in FindMy.py prints `private_key_b64`.

### Done

Your devices appear as `device_tracker` entities with companion battery and position sensors.

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
