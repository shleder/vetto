#!/usr/bin/env node

"use strict";

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const platform = process.platform;
const arch = process.arch;
const target = `${platform}-${arch}`;
const executable = platform === "win32" ? "vetto.exe" : "vetto";
const binary = path.join(__dirname, "..", "native", target, executable);

if (!fs.existsSync(binary)) {
  const supported = [
    "linux-x64",
    "linux-arm64",
    "darwin-x64",
    "darwin-arm64",
    "win32-x64",
  ];
  console.error(
    `vetto does not include a native binary for ${target}. ` +
      `Supported targets: ${supported.join(", ")}.`,
  );
  process.exitCode = 1;
} else {
  const child = spawn(binary, process.argv.slice(2), {
    stdio: "inherit",
    windowsHide: false,
  });

  child.on("error", (error) => {
    console.error(`Unable to start vetto: ${error.message}`);
    process.exitCode = 1;
  });

  child.on("close", (code, signal) => {
    if (signal) {
      console.error(`vetto terminated by signal ${signal}`);
      process.exitCode = 1;
    } else {
      process.exitCode = code === null ? 1 : code;
    }
  });
}
