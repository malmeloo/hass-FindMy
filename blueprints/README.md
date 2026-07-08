# FindMy - HA Automation Blueprints

Blueprints ship with the integration but are not auto-loaded by Home Assistant.
Import them manually via URL.

## `tag_zone_change.yaml`

Fires a notification when a tag enters or leaves a zone. Handles the common
"my bag/bike/laptop just left home" case out of the box.

Import URL:
```
https://raw.githubusercontent.com/malmeloo/hass-FindMy/main/blueprints/automation/tag_zone_change.yaml
```

Steps: Settings → Automations & Scenes → Blueprints → Import Blueprint →
paste URL. Then Create Automation from the imported blueprint and pick tag,
zone and notification target.

## `tag_stale.yaml`

Warns when a tag hasn't reported for X hours. Catches dead batteries,
firmware crashes, or physical removal (thief unpaired the tag / hidden in a
Faraday cage).

Import URL:
```
https://raw.githubusercontent.com/malmeloo/hass-FindMy/main/blueprints/automation/tag_stale.yaml
```

## Notes on notification targets

For the `notify_service` input:
- Leave empty for a persistent notification (in the HA UI notification bell)
- `notify.mobile_app_<devicename>` for the HA Companion App (mobile push)
- `notify.telegram` if you configured Telegram
- Any other `notify.*` service you have

To find your service name: Developer Tools → Services → search "notify".
