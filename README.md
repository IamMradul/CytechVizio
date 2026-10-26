# 🌐 cyteckvizio // Real-Time 3D Cyber Threat Globe

A high-performance, real-time cyber attack visualization globe styled like **Kaspersky's Cybermap**. Implemented as an interactive 3D spherical world globe in a single self-contained HTML file (HTML5 Canvas, CSS, and Vanilla JavaScript with zero build step), backed by an optional Node.js Express proxy server for local GeoIP enrichment and API key protection.

---

## 📸 Key Visual & Technical Highlights

- **3D Dotted Rotating Globe**: Spherical 3D planet created by projecting simplified continent polygons onto a spherical point-cloud of glowing matrix dots (**zero external textures or map tiles needed**).
- **Sub-Orbital Parabolic Arcs**: 3D Great Circle trajectories (calculated via Spherical Linear Interpolation - Slerp) that arc into outer orbit, featuring luminous comet heads, altitude laser tethers, ground drop shadows, and impact shockwave ripples.
- **Dynamic Threat Classification**: One distinctive neon color per attack type:
  - ⚡ **DDoS**: `#ff2a6d` (Cyber Pink/Red)
  - ☣ **Malware**: `#00f59b` (Matrix Green)
  - 🎣 **Phishing**: `#05d9e8` (Cyan Alert)
  - 🔑 **Brute force**: `#bf55ec` (Laser Violet)
  - ⚙ **Exploit**: `#ffb800` (Amber Threat Gold)
  - 🔒 **Ransomware**: `#ff003c` (Blood Red Lockdown)
- **Full 3D Orbital Controls**: Smooth mouse and touch drag yaw/pitch rotation, physics momentum inertia, wheel & pinch zoom, and automatic idle planetary spin.
- **Cyberpunk HUD Command Center**: Live DEFCON threat condition badges (1-4), rolling Attacks Per Second (APS) sparkline graph, audio equalizer bars, and tactical telemetry readout.
- **Interactive Filtering**: Click any threat vector in the left HUD to filter its arcs on or off in real-time.
- **Dual Themes**: Dark sci-fi mode (default) and clean high-tech light mode via CSS custom properties.
- **Synthesized Audio Engine**: Built-in sound effects using Web Audio API (launch clicks & deep impact sub-bass thuds) with zero external media files.
- **Accessibility & Responsiveness**: Respects `prefers-reduced-motion` and seamlessly adapts from desktop HUD view down to mobile view.

---

## 🚀 Quick Start Guide

### Option 1: Standalone Client (No Server Required)
You can open `index.html` directly in any modern web browser:
```bash
# On Windows
start index.html

# On macOS
open index.html

# On Linux
xdg-open index.html
```
The visual map will immediately initialize in **Autonomous Threat Simulator Mode** with zero dependencies.

---

### Option 2: Running with Node.js Proxy Server (Recommended)
The Node.js proxy server enriches IPs locally using MaxMind GeoLite2, protects upstream threat intelligence API keys, and exposes a real-time Server-Sent Events (SSE) telemetry stream.

#### 1. Install Dependencies
```bash
npm install
```

#### 2. Configure Environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Optionally configure your keys in `.env`:
```env
PORT=3000
HONEYDB_API_ID=your_honeydb_api_id
HONEYDB_API_KEY=your_honeydb_api_key
OFFSEQ_API_BASE=https://mirage.offseq.com
```

#### 3. Start the Server
```bash
npm start
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🏗️ Architecture & Data Layer

### The Core Ingestion Function
Everything visual in the application passes strictly through one core function:
```javascript
pushAttack({
  src: [nameOrCountry, longitude, latitude],
  dst: [sensorName, longitude, latitude],
  type: 'DDoS' | 'Malware' | 'Phishing' | 'Brute force' | 'Exploit' | 'Ransomware',
  id: 'optional-unique-event-id'
});
```

### Pluggable Adapters Included
1. **Simulator Adapter (`SimulatorAdapter`)**:
   - Generates realistic, weighted geopolitical cyber attack events.
   - Automatic fallback when live feeds are unavailable or lack keys.
2. **Server-Sent Events Adapter (`SseAdapter`)**:
   - Streams live enriched attack telemetry from `/events`.
   - Automatic reconnection with exponential backoff.
3. **HoneyDB Adapter (`HoneyDbAdapter`)**:
   - Polls HoneyDB API for bad hosts every 15–30 seconds.
   - Converts bad hosts into attacks directed at your sensor network.
4. **OffSeq Mirage Adapter (`OffSeqAdapter`)**:
   - Polls aggregate threat counts from OffSeq Mirage Intel (`/api/intel/top/countries`).
   - Uses a jittered queue to emit events **proportionally and smoothly over the polling interval** rather than all at once.

---

## 🛠️ Instructions for Adding a New Adapter

Adding a new threat feed adapter takes less than 30 lines of code:

### Step 1: Extend `BaseAdapter`
Create a class extending `BaseAdapter` inside `index.html`:

```javascript
class CustomThreatFeedAdapter extends BaseAdapter {
  constructor(hub, endpointUrl) {
    super('CustomFeed', hub);
    this.endpointUrl = endpointUrl;
    this.pollTimer = null;
  }

  start() {
    super.start();
    this.setStatus('live', 'CUSTOM FEED LIVE');
    this.poll();
  }

  stop() {
    super.stop();
    if (this.pollTimer) clearTimeout(this.pollTimer);
  }

  async poll() {
    if (!this.active) return;
    try {
      const response = await fetch(this.endpointUrl);
      const items = await response.json();

      // Convert incoming items to pushAttack format
      const batch = items.map(item => ({
        id: `custom-${item.id}`,
        src: [item.country || 'Attacker', item.lon, item.lat],
        dst: [this.getRandomSensor().name, this.getRandomSensor().lon, this.getRandomSensor().lat],
        type: item.type || 'Malware'
      }));

      // Smoothly spread the batch over 20 seconds so arcs flow naturally
      this.dispatchBatchSmoothly(batch, 20);
    } catch (err) {
      console.warn('[CustomFeed] Error:', err);
      this.setStatus('simulated', 'CUSTOM FEED (ERROR)');
    }

    // Schedule next poll in 20 seconds
    this.pollTimer = setTimeout(() => this.poll(), 20000);
  }
}
```

### Step 2: Register in Application Initialization
Add your adapter instance to the `adapters` dictionary in the DOMContentLoaded block:

```javascript
const adapters = {
  simulator: new SimulatorAdapter(attackHub),
  sse:       new SseAdapter(attackHub),
  honeydb:   new HoneyDbAdapter(attackHub),
  offseq:    new OffSeqAdapter(attackHub),
  custom:    new CustomThreatFeedAdapter(attackHub, '/api/my-feed') // <-- Add here
};
```

---

## 🛡️ Attribution & Security Disclaimers

### Data Sources & Attribution
- **[HoneyDB](https://honeydb.io)**: Threat intelligence and bad-host honeypot telemetry provided by the HoneyDB Community API.
- **[OffSeq Mirage](https://offseq.com)**: Real-time intelligence on active network probes and targeted services.
- **[MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)**: IP geolocation databases provided under the Creative Commons Attribution-ShareAlike 4.0 International License.

### ⚠️ IP Spoofing Notice
> **Important Note:** In DDoS amplification, DNS reflection, NTP attacks, and SYN flood traffic, attacker source IPs are frequently spoofed at the transport layer. Displayed geographical origins represent telemetry routing observations, not necessarily the physical location of the threat actor.
