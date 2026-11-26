//
//  SafariWebExtensionHandler.swift
//  Jex Extension — native messaging endpoint for the Safari Web Extension.
//
//  Safari appex cannot reliably use connectNative (UUID churn). The background
//  script talks to jex over HTTP; this handler kickstarts LaunchAgent
//  ru.jex.nmcades-http when the bridge is down ("ensureBridge").
//

import SafariServices
import os.log

class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {

    func beginRequest(with context: NSExtensionContext) {
        let request = context.inputItems.first as? NSExtensionItem
        let message: Any?
        if #available(iOS 15.0, macOS 11.0, *) {
            message = request?.userInfo?[SFExtensionMessageKey]
        } else {
            message = request?.userInfo?["message"]
        }

        os_log(.default, "Jex SafariWebExtensionHandler message: %{public}@", String(describing: message))

        var reply: [String: Any] = ["echo": message as Any]
        if let dict = message as? [String: Any],
           (dict["cmd"] as? String) == "ensureBridge" {
            let ok = Self.ensureHttpBridge()
            reply = ["ok": ok, "cmd": "ensureBridge"]
        }

        let response = NSExtensionItem()
        if #available(iOS 15.0, macOS 11.0, *) {
            response.userInfo = [SFExtensionMessageKey: reply]
        } else {
            response.userInfo = ["message": reply]
        }
        context.completeRequest(returningItems: [response], completionHandler: nil)
    }

    @discardableResult
    private static func ensureHttpBridge() -> Bool {
        let candidates = [
            NSString(string: "~/devel/jex/cli/scripts/ensure-nmcades-http.sh").expandingTildeInPath,
            "/usr/local/libexec/jex/ensure-nmcades-http.sh",
        ]
        guard let script = candidates.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            os_log(.error, "Jex: ensure-nmcades-http.sh not found")
            return false
        }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/sh")
        task.arguments = [script]
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
            os_log(.default, "Jex: ensureHttpBridge status=%d", task.terminationStatus)
            // Give the agent a moment to bind the port.
            Thread.sleep(forTimeInterval: 0.4)
            return task.terminationStatus == 0
        } catch {
            os_log(.error, "Jex: ensureHttpBridge error %{public}@", String(describing: error))
            return false
        }
    }
}
