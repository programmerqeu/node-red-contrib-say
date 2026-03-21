# node-red-contrib-say

> Node-RED output node for text-to-speech (TTS).  
> Let your runtime speak messages from your flows.

[![NPM](https://nodei.co/npm/node-red-contrib-say.png?downloads=true)](https://nodei.co/npm/node-red-contrib-say/)

## What this node does

`node-red-contrib-say` adds a **`say`** node to the *output* section of the Node-RED palette.

When the node receives a message it:

- picks the text to speak from:
  - `Text` field in the node config, **or**
  - node `Name`, **or**
  - `msg.payload`
- chooses a voice (built-in or custom string, depending on your platform)
- chooses a speed factor
- uses the underlying [`say`](https://www.npmjs.com/package/say) library to speak the text on the host machine
- forwards the original `msg` to the next node when speaking finishes

This makes it easy to:

- announce sensor values (“Temperature is 21 degrees”)
- speak notifications on a kiosk / wallboard
- give audible feedback from flows on your local machine or home server

---

## Requirements

This node is a thin wrapper around the `say` package and relies on platform TTS tools:

- **macOS**
  - Uses the built-in `say` command.
  - No extra setup required in a default macOS install.
  - To list voices available on **that** machine, run in a terminal: `say -v '?'` (voices can differ by macOS version and installed language packs).

- **Linux**
  - The underlying [`say`](https://www.npmjs.com/package/say) package uses **[Festival](http://www.cstr.ed.ac.uk/projects/festival/) only** (for example `espeak-ng` is not used).
  - Install Festival using your package manager (for example on Debian/Ubuntu):

    ```bash
    sudo apt-get install festival
    ```

  - You also need a working audio stack on the host (for example ALSA, PulseAudio, or PipeWire) so Festival can play sound. Minimal or headless servers may need extra configuration or audio devices mapped into the environment.

  - **Docker and containers:** Base images often omit Festival and may not expose sound devices. Install Festival inside the image, install/configure audio, and pass through devices or use a suitable remote audio setup—otherwise the node cannot produce audible output.

- **Windows**
  - Uses a native PowerShell call to `SAPI.SpVoice`.
  - Works out‑of‑the‑box on standard Windows installations with PowerShell.

> The Node-RED container / host must have at least one working TTS backend installed and accessible from the command line, otherwise this node cannot speak.

---

## Installation

You can install the node either from the **Node-RED palette** or from your project directory.

### From the Node-RED palette

1. Open the Node-RED editor.
2. Go to **Menu → Manage palette → Install**.
3. Search for **`node-red-contrib-say`**.
4. Click **Install**.

### From your project directory

In your Node-RED user directory (often `~/.node-red` or your project folder):

```bash
pnpm add node-red-contrib-say
```

Then restart Node-RED so the new node is loaded.

---

## Using the `say` node

After installation you will find the **`say`** node under **Output** in the Node-RED palette.

### Inputs

- **`msg.payload`**  
  - Used as the text to speak if neither the **Text** field nor the node **Name** is set.
  - Can be a string, number, or anything that can be converted to a string.

### Outputs

- **1 output**  
  - The original `msg` is forwarded once speaking is finished or an error occurred.
  - On error the node will also log via `node.error(err)`.

---

## Node configuration

The editor dialog (`say.html`) exposes the following fields:

- **Name**
  - Optional label shown under the node in the flow.
  - If **Text** is empty, the *Name* is also used as the spoken text (fallback).

- **Text**
  - Optional text to speak.
  - Highest priority:
    - If set, this value is spoken regardless of `msg.payload`.
  - Leave empty if you want to drive the spoken text entirely via `msg.payload`.

- **Voice**
  - Dropdown of available built‑in voices for your platform. The presets refer to the **Node-RED runtime** OS (Linux vs macOS), not necessarily the computer where you edit the flow.
  - The editor automatically hides non-matching preset groups when the runtime OS can be detected.
  - If runtime OS detection is unavailable, all preset groups remain visible as a safe fallback.
  - If a flow already uses a preset from another OS, that selected preset stays visible in the editor for compatibility.
  - Options:
    - `Standard` (empty value): use the default system voice.
    - `Specify voice by string (:)`: enables **Voice Name**.
    - Named voices for **Linux** (Festival voices like `Alan`, `Nick`, `SLT`, …).
    - Named voices for **macOS** (e.g. `Alex`, `Bruce`, `Kathy`, `Vicki`, …).

- **Voice Name** (shown only when **Voice** is set to *Specify voice by string*)
  - Free‑form string passed to the underlying TTS engine as the voice name.
  - Use this when your platform has additional voices that are not listed in the dropdown.

- **Speed**
  - Playback speed factor.
  - Default: `1.0`.
  - Range in the UI: `0.1` – `2.0`, step `0.1`.
  - Internally converted to a `Number` and passed to `say.speak`.

### Text selection priority

When a message arrives, the node chooses the text to speak in this order:

1. **`config.text`** (Text field), if not empty
2. **`config.name`** (Name), if Text is empty
3. **`msg.payload`**, if neither Text nor Name are provided

---

## Example flows

### 1. Speak a fixed message on deploy or button press

1. Add an **Inject** node.
2. Set it to send any payload (e.g. `"trigger"`).
3. Add a **say** node.
4. Open the **say** node dialog and set:
   - **Text**: `Hello from Node-RED`
   - **Voice**: `Standard`
   - **Speed**: `1.0`
5. Wire **Inject → say** and deploy.

Whenever you click the inject button, your machine will say:  
**“Hello from Node-RED”**.

### 2. Speak dynamic payload values

1. Add an **Inject** node and configure:
   - **Payload** type: *string*
   - **Payload**: `Temperature is 21 degrees`
2. Add a **say** node with:
   - leave **Text** empty
   - optional **Name**: `Speak temperature`
3. Wire **Inject → say** and deploy.

On each inject, the `say` node will speak the string from `msg.payload`.

### 3. Use a custom voice string

1. On a platform that supports multiple voices (macOS / Festival), add a **say** node.
2. In the node configuration:
   - Set **Voice** to `Specify voice by string`.
   - Set **Voice Name** to a valid voice identifier, e.g. `Alex` or another voice name recognised by your OS.
3. Leave **Text** empty and provide text via an **Inject** or **Function** node.

The node will now try to speak using the custom voice you configured.

---

## Error handling

- If the underlying `say` call fails, the node:
  - calls `node.error(err)` for visibility in the debug sidebar / logs,
  - **does not** send the message further (no `node.send`) in that case.
- Make sure the host has a working TTS engine installed and available on the command line.

---

## Contributing

Development setup, linting, and git hooks are described in [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License & credits

- **License:** MIT – see [`LICENSE`](LICENSE).
- **Based on:** [`say`](https://www.npmjs.com/package/say) by Marak – huge thanks for the original library.
- **Built for:** [Node-RED](https://nodered.org/), an open-source flow-based programming tool for wiring together hardware devices, APIs and online services.
