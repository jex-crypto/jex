// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
//
//  AppDelegate.swift
//  Jex
//
//  Safari cannot spawn Native Messaging from the appex the way Chrome does.
//  The HTTP bridge (127.0.0.1:18787) is owned by LaunchAgent ru.jex.nmcades-http;
//  this app only kickstarts it and syncs the Safari NMH UUID.
//

import Cocoa

@main
class AppDelegate: NSObject, NSApplicationDelegate {

    func applicationDidFinishLaunching(_ notification: Notification) {
        Self.syncSafariNativeMessagingHost()
        Self.ensureHttpBridge()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Closing the prefs window must not tear down the LaunchAgent bridge.
        return true
    }

    private static func ensureHttpBridge() {
        let script = NSString(string: "~/devel/jex/cli/scripts/ensure-nmcades-http.sh")
            .expandingTildeInPath
        guard FileManager.default.isExecutableFile(atPath: script)
            || FileManager.default.fileExists(atPath: script) else {
            NSLog("Jex: ensure-nmcades-http.sh not found at %@", script)
            return
        }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/sh")
        task.arguments = [script]
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
            NSLog("Jex: kickstarted LaunchAgent ru.jex.nmcades-http (status %d)", task.terminationStatus)
        } catch {
            NSLog("Jex: ensureHttpBridge failed: %@", String(describing: error))
        }
    }

    private static func syncSafariNativeMessagingHost() {
        let script = NSString(string: "~/devel/jex/cli/scripts/sync-safari-nmh.sh").expandingTildeInPath
        guard FileManager.default.fileExists(atPath: script) else { return }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/sh")
        task.arguments = [script]
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        try? task.run()
        task.waitUntilExit()
    }
}
