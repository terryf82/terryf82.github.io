---
layout: post
title:  "BlueTeamLabsOnline: Deep Blue"
date:   2021-10-27 13:15:00 +1000
categories: blue-team
tags: deep-blue-cli event-viewer power-shell windows
excerpt_separator: <!--more-->
---

**Deep Blue** is a Windows-based investigation authored by BTLO.

<!--more-->

<p align="center"><img src="/assets/images/deep-blue/main.jpg" /></p>

The scenario involves a compromised Windows workstation, with indications that publicly-reachable RDP was the entrypoint. Two `.evtx` (Event Viewer) log files are provided, with instructions to examine the file using [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI), a PowerShell module for Windows-based threat hunting.