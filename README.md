node-red-contrib-say
====================

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/programmerqeu/node-red-contrib-say/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/programmerqeu/node-red-contrib-say/?branch=master)
[![Build Status](https://scrutinizer-ci.com/g/programmerqeu/node-red-contrib-say/badges/build.png?b=master)](https://scrutinizer-ci.com/g/programmerqeu/node-red-contrib-say/build-status/master)
[![Join the chat at https://gitter.im/programmerqeu/node-red-contrib-say](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/programmerqeu/node-red-contrib-say?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Output node for node-red  for tts (text to speech).
Let your computer speak the entered text.

## Preparation

### OSX
You should be lucky. All you need is preinstalled.

### Linux
Linux support involves the use of [Festival](http://www.cstr.ed.ac.uk/projects/festival/), which uses decidedly less friendly names for its voices.

### Windows
It simply does a native shell call to PowerShell and it works fine for standard use.

## Install

Switch to your Node-RED project directory and run the following command:
```
npm install node-red-contrib-say
```

## Thanks

1.  This node is based on [say.js](https://www.npmjs.com/package/say). Special thanks to Marak!
2.  [NodeRED](nodered.org) is the main tool for the internet of things. It is a open source project is invented and maintained bei IBM.
