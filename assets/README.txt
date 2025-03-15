# GopherStrike Assets

This directory contains assets for the GopherStrike project.

## Required Assets

For a professional-looking project, please create and add the following assets:

### Logo

- Create `gopherstrike-logo.png` - A custom logo for the project
- Recommended size: 500x500px
- The user mentioned they already have an AI-generated logo ready to use

### Screenshots

Add the following screenshots to the `screenshots` directory:

1. `screenshot-main-menu.png` - The main menu of GopherStrike
2. `screenshot-port-scanner.png` - The port scanner in action
3. `screenshot-subdomain-scanner.png` - The subdomain scanner in action
4. `screenshot-osint.png` - The OSINT tool in action

### Demo GIF

- Create `gopherstrike-demo.gif` - A GIF showing GopherStrike in action
- Recommended length: 10-15 seconds
- Show a brief walkthrough of selecting a tool and using it

## How to Create These Assets

### Screenshots

You can capture screenshots using:

- On macOS: Press `Command + Shift + 4`, then select the area
- On Windows: Use the Snipping Tool or press `Win + Shift + S`
- On Linux: Use tools like Flameshot, GIMP, or press `PrtScn`

### Terminal GIFs

To create terminal GIFs, you can use:

1. **Terminalizer** (cross-platform):
   ```bash
   npm install -g terminalizer
   terminalizer record demo
   terminalizer render demo
   ```

2. **asciinema** + **asciicast2gif** (Linux/macOS):
   ```bash
   # Record
   asciinema rec demo.cast
   # Convert to GIF
   docker run --rm -v $PWD:/data asciinema/asciicast2gif demo.cast gopherstrike-demo.gif
   ```

3. **LICEcap** (Windows/macOS):
   - Download from https://www.cockos.com/licecap/
   - Use the app to record your terminal

4. **Gifox** (macOS):
   - Available in the App Store

Once created, place the GIF file in the `assets` directory as `gopherstrike-demo.gif`.

## Asset Optimization

Before committing assets:

1. Optimize images:
   ```bash
   # Using ImageOptim CLI (if available)
   imageoptim assets/*.png assets/screenshots/*.png
   ```

2. Optimize GIFs:
   ```bash
   # Using gifsicle (if available)
   gifsicle -O3 assets/gopherstrike-demo.gif -o assets/gopherstrike-demo.gif
   ```

Smaller file sizes will make your repository more efficient to clone and your README load faster on GitHub. 