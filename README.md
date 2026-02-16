# PiTiZed

A desktop PTZ camera controller built with Electron. Manage multiple cameras from a single interface with live feeds, AI-powered subject tracking, and multi-camera settings synchronization.

## Features

### Multi-Camera Management
- Add, remove, and rename cameras by IP address
- Network scanning for camera discovery
- Live snapshot feed with FPS monitoring
- HTTP Digest Authentication (MD5 and SHA-256)

### PTZ Control
- Pan, tilt, and zoom with adjustable speed
- Focus control (auto/manual, near/far)
- Home position and presets
- OSD navigation

### AI Subject Tracking
- Two ML model options: **COCO-SSD** (bounding box) and **MoveNet** (pose estimation)
- Shot profiles: Wide, Medium, and Tight (torso-up framing)
- Proportional speed control with smooth acceleration
- Auto-zoom to maintain consistent framing
- Pursuit mode on temporary subject loss
- Native camera auto-tracking toggle (for cameras that support it)

### Image & Exposure Controls
- White Balance: Auto, Indoor, Outdoor, One Push, Manual, VAR
- Red/Blue gain, Saturation, Luminance, Contrast, Hue, Sharpness
- Exposure modes: Auto, Manual, Shutter Priority, Iris Priority
- Gain, Iris, Shutter, Backlight, DRC, Noise Reduction
- Intelligent White Balance analysis with color temperature estimation

### Multi-Camera Sync
- Synchronize image, white balance, and exposure settings across cameras
- Select target cameras and sync from a source camera in one click

### Video & Audio Configuration
- Stream codec, bitrate, resolution, and FPS settings
- Audio parameter control
- Snapshot capture and save to disk

## Getting Started

### Prerequisites
- Node.js
- npm

### Install & Run

```bash
npm install
npm start
```

### Build

```bash
# Package for current platform
npm run dist
```

## Usage

1. Launch the app and click **Add Camera**
2. Enter the camera's IP address and credentials (default: `admin` / `admin`)
3. The live feed and controls appear once connected
4. Expand a camera card to access image, exposure, and tracking controls
5. Use the **Sync** panel to match settings across multiple cameras

## Tested Devices

| Camera | API | Status |
|--------|-----|--------|
| PTZOptics Move SE | G3 | Tested |
| PTZOptics Move 4K | G3 | Should work (untested) |
| PTZOptics Link 4K | G3 | Should work (untested) |
| PTZOptics Studio Pro | G3 | Should work (untested) |

PiTiZed is built against the PTZOptics G3 HTTP API. Any PTZOptics camera running G3 firmware should be compatible. Older G2 cameras may have partial support.

## Tech Stack

- **Electron** — desktop shell
- **TensorFlow.js** — AI tracking (COCO-SSD, MoveNet)
- **Vanilla JS/HTML/CSS** — single-file UI, no framework dependencies
