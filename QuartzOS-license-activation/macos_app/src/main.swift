import Cocoa
import Foundation

final class ActivationAppController: NSObject, NSApplicationDelegate {
    private var window: NSWindow!
    private let repoPathField = NSTextField(string: "")
    private let keyField = NSTextField(string: "")
    private let termsCheckbox = NSButton(checkboxWithTitle: "I accept QuartzOS license terms", target: nil, action: nil)
    private let statusLabel = NSTextField(labelWithString: "Status: Waiting for key verification.")
    private let outputView = NSTextView()
    private var lastVerifiedKey: String = ""
    private var lastVerifyPassed = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildUI()
        preloadDefaults()
        appendOutput("QuartzOS License Activation ready.")
        appendOutput("This app is public activation-only. Issuer Pro remains dev-only.")
    }

    private func buildUI() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 920, height: 640),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = "QuartzOS License Activation"
        window.makeKeyAndOrderFront(nil)

        guard let content = window.contentView else {
            return
        }

        let heading = NSTextField(labelWithString: "QuartzOS License Activation")
        heading.font = NSFont.systemFont(ofSize: 24, weight: .bold)

        let subheading = NSTextField(labelWithString: "Public app for verifying a key and generating unlock commands for QuartzOS VM lock mode.")
        subheading.textColor = .secondaryLabelColor

        let repoLabel = NSTextField(labelWithString: "QuartzOS repo path")
        repoLabel.font = NSFont.systemFont(ofSize: 12, weight: .semibold)

        repoPathField.placeholderString = "/Users/qian/Music/OS"

        let keyLabel = NSTextField(labelWithString: "License key (QOS3)")
        keyLabel.font = NSFont.systemFont(ofSize: 12, weight: .semibold)

        keyField.placeholderString = "QOS3-XXXXXXXX-XX-XX-XXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX"

        termsCheckbox.state = .on

        statusLabel.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .medium)

        outputView.isEditable = false
        outputView.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        outputView.string = ""

        let scroll = NSScrollView()
        scroll.documentView = outputView
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = false
        scroll.drawsBackground = true

        let validateButton = makeButton(title: "Verify Key", action: #selector(onVerify))
        let copyButton = makeButton(title: "Copy Unlock Commands", action: #selector(onCopyCommands))
        let autoActivateButton = makeButton(title: "Activate Running VM", action: #selector(onAutoActivate))
        let saveButton = makeButton(title: "Save Commands File", action: #selector(onSaveCommands))
        let termsButton = makeButton(title: "Open Terms", action: #selector(onOpenTerms))
        let resetButton = makeButton(title: "Reset", action: #selector(onReset))

        let buttonRow = NSStackView(views: [validateButton, copyButton, autoActivateButton, saveButton, termsButton, resetButton])
        buttonRow.orientation = .horizontal
        buttonRow.alignment = .centerY
        buttonRow.spacing = 10

        let root = NSStackView(views: [
            heading,
            subheading,
            repoLabel,
            repoPathField,
            keyLabel,
            keyField,
            termsCheckbox,
            buttonRow,
            statusLabel,
            scroll,
        ])
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 10
        root.translatesAutoresizingMaskIntoConstraints = false

        content.addSubview(root)

        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            root.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            root.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            root.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20),
            repoPathField.widthAnchor.constraint(equalTo: root.widthAnchor),
            keyField.widthAnchor.constraint(equalTo: root.widthAnchor),
            buttonRow.widthAnchor.constraint(equalTo: root.widthAnchor),
            scroll.widthAnchor.constraint(equalTo: root.widthAnchor),
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 320),
        ])
    }

    private func preloadDefaults() {
        repoPathField.stringValue = detectDefaultRepoPath()
    }

    private func detectDefaultRepoPath() -> String {
        let fm = FileManager.default
        var candidates: [String] = []

        let cwd = fm.currentDirectoryPath
        candidates.append(cwd)

        let bundlePath = Bundle.main.bundlePath
        let bundleURL = URL(fileURLWithPath: bundlePath)
        candidates.append(bundleURL.deletingLastPathComponent().path)
        candidates.append(bundleURL.deletingLastPathComponent().deletingLastPathComponent().path)

        candidates.append("/Users/qian/Music/OS")

        for candidate in candidates {
            let normalized = trim(candidate)
            if normalized.isEmpty {
                continue
            }
            let script = (normalized as NSString).appendingPathComponent("QuartzOS-license-issuer/issue_license.py")
            if fm.fileExists(atPath: script) {
                return normalized
            }
        }

        return "/Users/qian/Music/OS"
    }

    private func makeButton(title: String, action: Selector) -> NSButton {
        let button = NSButton(title: title, target: self, action: action)
        button.bezelStyle = .rounded
        return button
    }

    private func trim(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func normalizedKey() -> String {
        trim(keyField.stringValue).uppercased()
    }

    private func issuerScriptPath(repoPath: String) -> String {
        (repoPath as NSString).appendingPathComponent("QuartzOS-license-issuer/issue_license.py")
    }

    private func autoActivationScriptPath(repoPath: String) -> String {
        (repoPath as NSString).appendingPathComponent("tools/auto-activate-vm-license.sh")
    }

    private func termsPath(repoPath: String) -> String {
        (repoPath as NSString).appendingPathComponent("TERMS_AND_CONDITIONS.md")
    }

    private func appendOutput(_ text: String) {
        let current = outputView.string
        let next = current + (current.isEmpty ? "" : "\n") + text
        outputView.string = next
        outputView.scrollToEndOfDocument(nil)
    }

    private func runVerify(scriptPath: String, key: String) -> (Int32, String)? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", scriptPath, "verify", "--key", key]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let text = String(data: data, encoding: .utf8) ?? "<non-utf8 output>"
            return (process.terminationStatus, text)
        } catch {
            appendOutput("error: failed to run verifier: \(error.localizedDescription)")
            return nil
        }
    }

    private func runTool(arguments: [String]) -> (Int32, String)? {
        guard !arguments.isEmpty else {
            return nil
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let text = String(data: data, encoding: .utf8) ?? "<non-utf8 output>"
            return (process.terminationStatus, text)
        } catch {
            appendOutput("error: failed to run helper: \(error.localizedDescription)")
            return nil
        }
    }

    private func parseConsumerMonthly(output: String) -> Bool {
        let lower = output.lowercased()
        let tierAllowed = (
            lower.contains("tier_code: 0x01 (consumer)") ||
            lower.contains("tier_code: 0x02 (enterprise)") ||
            lower.contains("tier_code: 0x03 (educational)") ||
            lower.contains("tier_code: 0x04 (server)") ||
            lower.contains("tier_code: 0x09 (oem)")
        )
        let hasSubscription = lower.contains("policy_bits:") && lower.contains("subscription")
        let notRevoked = lower.contains("revoked: no")
        let issued = lower.contains("issued: yes")
        let validSignature = lower.contains("signature: valid")
        let notLegacy = lower.contains("legacy: no")
        let notDevOnly = !lower.contains("development_only")
        return tierAllowed && hasSubscription && notRevoked && issued && validSignature && notLegacy && notDevOnly
    }

    private func updateStatus(_ text: String, ok: Bool) {
        statusLabel.stringValue = "Status: \(text)"
        statusLabel.textColor = ok ? NSColor.systemGreen : NSColor.systemRed
    }

    private func buildUnlockCommands(for key: String) -> String {
        [
            "license terms",
            "license accept",
            "license reload",
            "license activate \(key)",
            "license unlock",
            "license status",
        ].joined(separator: "\n")
    }

    @objc private func onVerify() {
        let repoPath = trim(repoPathField.stringValue)
        let key = normalizedKey()

        guard !repoPath.isEmpty else {
            updateStatus("Repository path is required.", ok: false)
            appendOutput("error: repository path is empty")
            return
        }
        guard !key.isEmpty else {
            updateStatus("Enter a license key.", ok: false)
            appendOutput("error: key field is empty")
            return
        }

        let scriptPath = issuerScriptPath(repoPath: repoPath)
        guard FileManager.default.fileExists(atPath: scriptPath) else {
            updateStatus("Verifier script missing.", ok: false)
            appendOutput("error: script not found at \(scriptPath)")
            return
        }

        appendOutput("verify: running public validation")
        guard let (exitCode, output) = runVerify(scriptPath: scriptPath, key: key) else {
            updateStatus("Verifier failed to start.", ok: false)
            return
        }

        appendOutput(output)

        let meetsTier = parseConsumerMonthly(output: output)
        if exitCode == 0 && meetsTier {
            lastVerifiedKey = key
            lastVerifyPassed = true
            updateStatus("Key verified for Consumer Monthly tier.", ok: true)
            appendOutput("verify: key accepted for unlock flow")
        } else if exitCode == 0 {
            lastVerifyPassed = false
            updateStatus("Key valid but not Consumer Monthly tier.", ok: false)
            appendOutput("verify: key exists but does not satisfy Consumer Monthly requirement")
        } else {
            lastVerifyPassed = false
            updateStatus("Key verification failed.", ok: false)
            appendOutput("verify: activation key rejected")
        }
    }

    @objc private func onCopyCommands() {
        let key = normalizedKey()
        guard !key.isEmpty else {
            updateStatus("Enter a key before copying commands.", ok: false)
            appendOutput("error: key field is empty")
            return
        }
        guard termsCheckbox.state == .on else {
            updateStatus("Terms checkbox must be enabled.", ok: false)
            appendOutput("error: terms checkbox is off")
            return
        }
        if !lastVerifyPassed || lastVerifiedKey != key {
            updateStatus("Verify this key first.", ok: false)
            appendOutput("error: key must be verified before command export")
            return
        }

        let commands = buildUnlockCommands(for: key)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(commands, forType: .string)
        updateStatus("Unlock commands copied to clipboard.", ok: true)
        appendOutput("copied unlock command sequence to clipboard")
    }

    @objc private func onSaveCommands() {
        let key = normalizedKey()
        guard !key.isEmpty else {
            updateStatus("Enter a key before saving commands.", ok: false)
            appendOutput("error: key field is empty")
            return
        }
        guard termsCheckbox.state == .on else {
            updateStatus("Terms checkbox must be enabled.", ok: false)
            appendOutput("error: terms checkbox is off")
            return
        }
        if !lastVerifyPassed || lastVerifiedKey != key {
            updateStatus("Verify this key first.", ok: false)
            appendOutput("error: key must be verified before command export")
            return
        }

        let panel = NSSavePanel()
        panel.title = "Save QuartzOS unlock commands"
        panel.nameFieldStringValue = "quartzos-unlock-commands.txt"
        panel.allowedContentTypes = [.plainText]
        panel.canCreateDirectories = true

        guard panel.runModal() == .OK, let url = panel.url else {
            appendOutput("save canceled")
            return
        }

        let commands = buildUnlockCommands(for: key) + "\n"
        do {
            try commands.write(to: url, atomically: true, encoding: .utf8)
            updateStatus("Commands saved.", ok: true)
            appendOutput("saved commands to \(url.path)")
        } catch {
            updateStatus("Failed to save commands.", ok: false)
            appendOutput("error: failed to save commands: \(error.localizedDescription)")
        }
    }

    @objc private func onAutoActivate() {
        let repoPath = trim(repoPathField.stringValue)
        let key = normalizedKey()

        guard !repoPath.isEmpty else {
            updateStatus("Repository path is required.", ok: false)
            appendOutput("error: repository path is empty")
            return
        }
        guard !key.isEmpty else {
            updateStatus("Enter a key before auto activation.", ok: false)
            appendOutput("error: key field is empty")
            return
        }
        guard termsCheckbox.state == .on else {
            updateStatus("Terms checkbox must be enabled.", ok: false)
            appendOutput("error: terms checkbox is off")
            return
        }
        if !lastVerifyPassed || lastVerifiedKey != key {
            updateStatus("Verify this key first.", ok: false)
            appendOutput("error: key must be verified before auto activation")
            return
        }

        let helperScript = autoActivationScriptPath(repoPath: repoPath)
        guard FileManager.default.fileExists(atPath: helperScript) else {
            updateStatus("Auto activation helper missing.", ok: false)
            appendOutput("error: helper script missing at \(helperScript)")
            return
        }

        appendOutput("auto-activate: sending unlock sequence to running VM")
        guard let (exitCode, output) = runTool(arguments: ["bash", helperScript, key]) else {
            updateStatus("Auto activation helper failed to start.", ok: false)
            return
        }
        if !trim(output).isEmpty {
            appendOutput(output)
        }
        if exitCode == 0 {
            updateStatus("Auto activation sequence sent to VM.", ok: true)
            appendOutput("auto-activate: done")
        } else {
            updateStatus("Auto activation failed.", ok: false)
            appendOutput("auto-activate: helper returned non-zero exit")
        }
    }

    @objc private func onOpenTerms() {
        let repoPath = trim(repoPathField.stringValue)
        let path = termsPath(repoPath: repoPath)
        guard FileManager.default.fileExists(atPath: path) else {
            updateStatus("Terms file not found.", ok: false)
            appendOutput("error: terms file missing at \(path)")
            return
        }
        NSWorkspace.shared.open(URL(fileURLWithPath: path))
        appendOutput("opened terms file: \(path)")
    }

    @objc private func onReset() {
        keyField.stringValue = ""
        termsCheckbox.state = .on
        lastVerifiedKey = ""
        lastVerifyPassed = false
        updateStatus("Waiting for key verification.", ok: true)
        outputView.string = ""
        appendOutput("reset complete")
    }
}

let app = NSApplication.shared
let delegate = ActivationAppController()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.activate(ignoringOtherApps: true)
app.run()
