import Cocoa
import Foundation
import UniformTypeIdentifiers

final class AdminConsoleController: NSObject, NSApplicationDelegate {
    private var window: NSWindow!

    private let repoPathField = NSTextField(string: "")
    private let passwordField = NSSecureTextField(string: "")
    private let ownerField = NSTextField(string: "admin")
    private let keyField = NSTextField(string: "")
    private let issueCountField = NSTextField(string: "1")
    private let tierPopup = NSPopUpButton(frame: .zero, pullsDown: false)

    private let statusLabel = NSTextField(labelWithString: "Status: Ready")
    private let outputView = NSTextView()

    private var actionButtons: [NSButton] = []
    private var stopButton: NSButton!

    private var activeProcess: Process?
    private var taskRunning = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildUI()
        preloadDefaults()
        appendOutput("QuartzOS Admin Console ready.")
        appendOutput("Security-first mode: only allowlisted operations are available.")
    }

    private func buildUI() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1180, height: 760),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = "QuartzOS Admin Console"
        window.makeKeyAndOrderFront(nil)

        guard let content = window.contentView else {
            return
        }

        let heading = NSTextField(labelWithString: "QuartzOS Admin Console")
        heading.font = NSFont.systemFont(ofSize: 28, weight: .bold)

        let subheading = NSTextField(labelWithString: "All-in-one admin operations with security-first guardrails.")
        subheading.textColor = .secondaryLabelColor

        let repoLabel = makeCaption("Repository Path")
        repoPathField.placeholderString = "/Users/qian/Music/OS"

        let passwordLabel = makeCaption("Issuer Admin Password (not saved)")
        passwordField.placeholderString = "Required for privileged license operations"

        let ownerLabel = makeCaption("Issue Owner")
        ownerField.placeholderString = "owner name"

        let keyLabel = makeCaption("License Key")
        keyField.placeholderString = "QOS3-XXXXXXXX-XX-XX-XXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX"

        let tierLabel = makeCaption("Tier")
        tierPopup.addItems(withTitles: [
            "consumer",
            "enterprise",
            "educational",
            "server",
            "oem",
            "dev_standard",
            "student_dev",
            "startup_dev",
            "open_lab",
        ])
        tierPopup.selectItem(withTitle: "consumer")

        let countLabel = makeCaption("Issue Count")
        issueCountField.placeholderString = "1"

        statusLabel.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .medium)

        outputView.isEditable = false
        outputView.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)

        let scroll = NSScrollView()
        scroll.documentView = outputView
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true

        let verifyButton = makeActionButton("Verify Key", #selector(onVerifyKey))
        let issueButton = makeActionButton("Issue Key", #selector(onIssueKey))
        let listButton = makeActionButton("List Keys", #selector(onListKeys))
        let revokeButton = makeActionButton("Revoke Key", #selector(onRevokeKey))
        let deactivateLegacyButton = makeActionButton("Deactivate Legacy", #selector(onDeactivateLegacy))
        let licenseRow = row([verifyButton, issueButton, listButton, revokeButton, deactivateLegacyButton])

        let auditButton = makeActionButton("Security Audit", #selector(onSecurityAudit))
        let healthButton = makeActionButton("Health Check", #selector(onHealth))
        let smokeButton = makeActionButton("Boot Smoke", #selector(onSmoke))
        let overhaulButton = makeActionButton("Deep Overhaul", #selector(onOverhaul))
        let securityRow = row([auditButton, healthButton, smokeButton, overhaulButton])

        let buildActivationButton = makeActionButton("Build Activation App", #selector(onBuildActivationApp))
        let buildIssuerButton = makeActionButton("Build Issuer App", #selector(onBuildIssuerApp))
        let openPolicyButton = makeActionButton("Open Security Policy", #selector(onOpenSecurityPolicy))
        let openSerialLogButton = makeActionButton("Open Serial Log", #selector(onOpenSerialLog))
        let exportButton = makeActionButton("Export Report", #selector(onExportReport))
        let clearButton = makeActionButton("Clear Output", #selector(onClearOutput))
        stopButton = makeActionButton("Stop Task", #selector(onStopTask))
        stopButton.isEnabled = false
        let opsRow = row([buildActivationButton, buildIssuerButton, openPolicyButton, openSerialLogButton, exportButton, clearButton, stopButton])

        let keyOwnerRow = NSStackView(views: [ownerLabel, ownerField, keyLabel, keyField])
        keyOwnerRow.orientation = .horizontal
        keyOwnerRow.spacing = 8
        keyOwnerRow.alignment = .centerY

        let issueRow = NSStackView(views: [tierLabel, tierPopup, countLabel, issueCountField])
        issueRow.orientation = .horizontal
        issueRow.spacing = 8
        issueRow.alignment = .centerY

        let root = NSStackView(views: [
            heading,
            subheading,
            repoLabel,
            repoPathField,
            passwordLabel,
            passwordField,
            keyOwnerRow,
            issueRow,
            securityRow,
            licenseRow,
            opsRow,
            statusLabel,
            scroll,
        ])
        root.orientation = .vertical
        root.spacing = 10
        root.alignment = .leading
        root.translatesAutoresizingMaskIntoConstraints = false

        content.addSubview(root)

        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 18),
            root.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -18),
            root.topAnchor.constraint(equalTo: content.topAnchor, constant: 18),
            root.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -18),
            repoPathField.widthAnchor.constraint(equalTo: root.widthAnchor),
            passwordField.widthAnchor.constraint(equalTo: root.widthAnchor),
            keyField.widthAnchor.constraint(greaterThanOrEqualToConstant: 560),
            ownerField.widthAnchor.constraint(greaterThanOrEqualToConstant: 140),
            issueCountField.widthAnchor.constraint(equalToConstant: 70),
            scroll.widthAnchor.constraint(equalTo: root.widthAnchor),
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 340),
        ])
    }

    private func preloadDefaults() {
        repoPathField.stringValue = detectDefaultRepoPath()
    }

    private func makeCaption(_ text: String) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        return label
    }

    private func makeActionButton(_ title: String, _ action: Selector) -> NSButton {
        let button = NSButton(title: title, target: self, action: action)
        button.bezelStyle = .rounded
        actionButtons.append(button)
        return button
    }

    private func row(_ views: [NSView]) -> NSStackView {
        let stack = NSStackView(views: views)
        stack.orientation = .horizontal
        stack.spacing = 8
        stack.alignment = .centerY
        return stack
    }

    private func trim(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func normalizedKey() -> String {
        trim(keyField.stringValue).uppercased()
    }

    private func detectDefaultRepoPath() -> String {
        let fm = FileManager.default
        let cwd = fm.currentDirectoryPath
        let bundlePath = Bundle.main.bundlePath
        let bundleURL = URL(fileURLWithPath: bundlePath)

        let candidates = [
            cwd,
            bundleURL.deletingLastPathComponent().path,
            bundleURL.deletingLastPathComponent().deletingLastPathComponent().path,
            "/Users/qian/Music/OS",
        ]

        for item in candidates {
            let path = trim(item)
            if path.isEmpty {
                continue
            }
            let makefile = (path as NSString).appendingPathComponent("Makefile")
            if fm.fileExists(atPath: makefile) {
                return path
            }
        }

        return "/Users/qian/Music/OS"
    }

    private func repoPath() -> String? {
        let repo = trim(repoPathField.stringValue)
        if repo.isEmpty {
            setStatus("Repository path is required.", ok: false)
            return nil
        }
        let makefile = (repo as NSString).appendingPathComponent("Makefile")
        guard FileManager.default.fileExists(atPath: makefile) else {
            setStatus("Invalid repository path.", ok: false)
            appendOutput("error: Makefile not found at \(makefile)")
            return nil
        }
        return repo
    }

    private func issuerScriptPath(in repo: String) -> String {
        (repo as NSString).appendingPathComponent("QuartzOS-license-issuer/issue_license.py")
    }

    private func ensureKey() -> String? {
        let key = normalizedKey()
        if key.isEmpty {
            setStatus("License key is required.", ok: false)
            appendOutput("error: license key field is empty")
            return nil
        }
        return key
    }

    private func ensurePassword() -> String? {
        let password = passwordField.stringValue
        if password.isEmpty {
            setStatus("Admin password is required for this action.", ok: false)
            appendOutput("error: issuer admin password is required")
            return nil
        }
        return password
    }

    private func askConfirmation(_ title: String, _ info: String) -> Bool {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = info
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }

    private func maskKey(_ key: String) -> String {
        if key.count < 16 {
            return key
        }
        let prefix = key.prefix(8)
        let suffix = key.suffix(8)
        return "\(prefix)...\(suffix)"
    }

    private func setStatus(_ text: String, ok: Bool) {
        statusLabel.stringValue = "Status: \(text)"
        statusLabel.textColor = ok ? NSColor.systemGreen : NSColor.systemRed
    }

    private func appendOutput(_ text: String) {
        let chunk = text.trimmingCharacters(in: .newlines)
        if chunk.isEmpty {
            return
        }
        let current = outputView.string
        outputView.string = current + (current.isEmpty ? "" : "\n") + chunk
        outputView.scrollToEndOfDocument(nil)
    }

    private func setBusy(_ busy: Bool) {
        taskRunning = busy
        for button in actionButtons {
            if button == stopButton {
                continue
            }
            button.isEnabled = !busy
        }
        stopButton.isEnabled = busy
    }

    private func startTask(
        name: String,
        repo: String,
        arguments: [String],
        display: String,
        extraEnv: [String: String] = [:]
    ) {
        if taskRunning {
            setStatus("Another task is running.", ok: false)
            return
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = arguments
        process.currentDirectoryURL = URL(fileURLWithPath: repo)

        var env = ProcessInfo.processInfo.environment
        for (k, v) in extraEnv {
            env[k] = v
        }
        process.environment = env

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        appendOutput("=== \(name) ===")
        appendOutput("$ \(display)")
        setStatus("Running \(name)...", ok: true)
        setBusy(true)

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty {
                return
            }
            let text = String(data: data, encoding: .utf8) ?? "<non-utf8 output>"
            DispatchQueue.main.async {
                self?.appendOutput(text)
            }
        }

        process.terminationHandler = { [weak self] proc in
            DispatchQueue.main.async {
                pipe.fileHandleForReading.readabilityHandler = nil
                self?.activeProcess = nil
                self?.setBusy(false)
                if proc.terminationStatus == 0 {
                    self?.setStatus("\(name) completed.", ok: true)
                } else {
                    self?.setStatus("\(name) failed (exit \(proc.terminationStatus)).", ok: false)
                }
                self?.appendOutput("--- task exit: \(proc.terminationStatus) ---")
            }
        }

        do {
            try process.run()
            activeProcess = process
        } catch {
            pipe.fileHandleForReading.readabilityHandler = nil
            activeProcess = nil
            setBusy(false)
            setStatus("Failed to launch task.", ok: false)
            appendOutput("error: \(error.localizedDescription)")
        }
    }

    @objc private func onSecurityAudit() {
        guard let repo = repoPath() else { return }
        startTask(
            name: "Security Audit",
            repo: repo,
            arguments: ["python3", "tools/admin_security_audit.py", "--repo", repo],
            display: "python3 tools/admin_security_audit.py --repo \(repo)"
        )
    }

    @objc private func onHealth() {
        guard let repo = repoPath() else { return }
        startTask(
            name: "Health Check",
            repo: repo,
            arguments: ["make", "health"],
            display: "make health"
        )
    }

    @objc private func onSmoke() {
        guard let repo = repoPath() else { return }
        startTask(
            name: "Boot Smoke Test",
            repo: repo,
            arguments: ["make", "smoke"],
            display: "make smoke"
        )
    }

    @objc private func onOverhaul() {
        guard let repo = repoPath() else { return }
        startTask(
            name: "Deep Overhaul",
            repo: repo,
            arguments: ["make", "overhaul"],
            display: "make overhaul"
        )
    }

    @objc private func onVerifyKey() {
        guard let repo = repoPath() else { return }
        guard let key = ensureKey() else { return }

        let script = issuerScriptPath(in: repo)
        guard FileManager.default.fileExists(atPath: script) else {
            setStatus("Issuer script missing.", ok: false)
            appendOutput("error: missing issuer script at \(script)")
            return
        }

        startTask(
            name: "Verify Key",
            repo: repo,
            arguments: ["python3", script, "verify", "--key", key],
            display: "python3 QuartzOS-license-issuer/issue_license.py verify --key \(maskKey(key))"
        )
    }

    @objc private func onIssueKey() {
        guard let repo = repoPath() else { return }
        guard let password = ensurePassword() else { return }

        let owner = trim(ownerField.stringValue)
        if owner.isEmpty {
            setStatus("Owner is required for issue.", ok: false)
            appendOutput("error: owner field is empty")
            return
        }

        let tier = tierPopup.selectedItem?.title ?? "consumer"
        let countText = trim(issueCountField.stringValue)
        let count = Int(countText) ?? 1
        if count < 1 || count > 50 {
            setStatus("Issue count must be 1..50.", ok: false)
            appendOutput("error: issue count out of range")
            return
        }

        let script = issuerScriptPath(in: repo)
        guard FileManager.default.fileExists(atPath: script) else {
            setStatus("Issuer script missing.", ok: false)
            appendOutput("error: missing issuer script at \(script)")
            return
        }

        startTask(
            name: "Issue Key",
            repo: repo,
            arguments: [
                "python3", script,
                "--password-env", "QOS_ISSUER_PASSWORD",
                "issue",
                "--owner", owner,
                "--tier", tier,
                "--version", "qos3",
                "--count", String(count),
            ],
            display: "python3 QuartzOS-license-issuer/issue_license.py --password-env QOS_ISSUER_PASSWORD issue --owner <owner> --tier <tier> --version qos3 --count <n>",
            extraEnv: ["QOS_ISSUER_PASSWORD": password]
        )
    }

    @objc private func onListKeys() {
        guard let repo = repoPath() else { return }
        guard let password = ensurePassword() else { return }

        let script = issuerScriptPath(in: repo)
        guard FileManager.default.fileExists(atPath: script) else {
            setStatus("Issuer script missing.", ok: false)
            appendOutput("error: missing issuer script at \(script)")
            return
        }

        startTask(
            name: "List Keys",
            repo: repo,
            arguments: [
                "python3", script,
                "--password-env", "QOS_ISSUER_PASSWORD",
                "list", "--show",
            ],
            display: "python3 QuartzOS-license-issuer/issue_license.py --password-env QOS_ISSUER_PASSWORD list --show",
            extraEnv: ["QOS_ISSUER_PASSWORD": password]
        )
    }

    @objc private func onRevokeKey() {
        guard let repo = repoPath() else { return }
        guard let password = ensurePassword() else { return }
        guard let key = ensureKey() else { return }

        if !askConfirmation("Revoke key?", "This key will be blocked from activation and usage.") {
            return
        }

        let script = issuerScriptPath(in: repo)
        guard FileManager.default.fileExists(atPath: script) else {
            setStatus("Issuer script missing.", ok: false)
            appendOutput("error: missing issuer script at \(script)")
            return
        }

        startTask(
            name: "Revoke Key",
            repo: repo,
            arguments: [
                "python3", script,
                "--password-env", "QOS_ISSUER_PASSWORD",
                "revoke",
                "--key", key,
                "--actor", "admin_console",
            ],
            display: "python3 QuartzOS-license-issuer/issue_license.py --password-env QOS_ISSUER_PASSWORD revoke --key \(maskKey(key)) --actor admin_console",
            extraEnv: ["QOS_ISSUER_PASSWORD": password]
        )
    }

    @objc private func onDeactivateLegacy() {
        guard let repo = repoPath() else { return }
        guard let password = ensurePassword() else { return }

        if !askConfirmation(
            "Deactivate all legacy licenses?",
            "This revokes all QOS1/QOS2 licenses and purges them from issuance records."
        ) {
            return
        }

        let script = issuerScriptPath(in: repo)
        guard FileManager.default.fileExists(atPath: script) else {
            setStatus("Issuer script missing.", ok: false)
            appendOutput("error: missing issuer script at \(script)")
            return
        }

        startTask(
            name: "Deactivate Legacy",
            repo: repo,
            arguments: [
                "python3", script,
                "--password-env", "QOS_ISSUER_PASSWORD",
                "deactivate-legacy",
                "--purge",
                "--actor", "admin_console",
            ],
            display: "python3 QuartzOS-license-issuer/issue_license.py --password-env QOS_ISSUER_PASSWORD deactivate-legacy --purge --actor admin_console",
            extraEnv: ["QOS_ISSUER_PASSWORD": password]
        )
    }

    @objc private func onBuildActivationApp() {
        guard let repo = repoPath() else { return }
        startTask(
            name: "Build Activation App",
            repo: repo,
            arguments: ["bash", "build_macos_activation_app.sh"],
            display: "bash build_macos_activation_app.sh"
        )
    }

    @objc private func onBuildIssuerApp() {
        guard let repo = repoPath() else { return }
        startTask(
            name: "Build Issuer App",
            repo: repo,
            arguments: ["bash", "build_macos_app.sh"],
            display: "bash build_macos_app.sh"
        )
    }

    @objc private func onOpenSecurityPolicy() {
        guard let repo = repoPath() else { return }
        let path = (repo as NSString).appendingPathComponent("SECURITY_POLICY.md")
        if !FileManager.default.fileExists(atPath: path) {
            setStatus("Security policy file missing.", ok: false)
            appendOutput("error: missing \(path)")
            return
        }
        NSWorkspace.shared.open(URL(fileURLWithPath: path))
        appendOutput("opened \(path)")
        setStatus("Opened security policy.", ok: true)
    }

    @objc private func onOpenSerialLog() {
        guard let repo = repoPath() else { return }
        let path = (repo as NSString).appendingPathComponent("build/qemu-serial.log")
        if !FileManager.default.fileExists(atPath: path) {
            setStatus("Serial log not found.", ok: false)
            appendOutput("error: serial log missing at \(path)")
            return
        }
        NSWorkspace.shared.open(URL(fileURLWithPath: path))
        appendOutput("opened \(path)")
        setStatus("Opened serial log.", ok: true)
    }

    @objc private func onExportReport() {
        let panel = NSSavePanel()
        panel.title = "Export Admin Console Report"
        panel.nameFieldStringValue = "quartzos-admin-report.txt"
        panel.canCreateDirectories = true
        panel.allowedContentTypes = [.plainText]

        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }

        let date = ISO8601DateFormatter().string(from: Date())
        let text = "QuartzOS Admin Console Report\nGenerated: \(date)\n\n\(outputView.string)\n"

        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            setStatus("Report exported.", ok: true)
            appendOutput("report saved: \(url.path)")
        } catch {
            setStatus("Failed to export report.", ok: false)
            appendOutput("error: \(error.localizedDescription)")
        }
    }

    @objc private func onClearOutput() {
        outputView.string = ""
        appendOutput("output cleared")
        setStatus("Ready", ok: true)
    }

    @objc private func onStopTask() {
        guard taskRunning, let proc = activeProcess else {
            return
        }
        proc.terminate()
        appendOutput("stop requested")
    }
}

let app = NSApplication.shared
let delegate = AdminConsoleController()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.activate(ignoringOtherApps: true)
app.run()
