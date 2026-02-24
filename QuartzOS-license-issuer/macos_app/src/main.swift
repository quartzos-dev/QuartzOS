import Cocoa

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow!

    private let repoPathField = NSTextField(string: "")
    private let hashPathField = NSTextField(string: "")
    private let passwordField = NSSecureTextField(string: "")

    private let ownerField = NSTextField(string: "")
    private let countField = NSTextField(string: "1")
    private let tierBox: NSComboBox = {
        let box = NSComboBox(frame: .zero)
        box.addItems(withObjectValues: [
            "consumer", "enterprise", "educational", "server",
            "dev_standard", "student_dev", "startup_dev", "open_lab", "oem"
        ])
        box.selectItem(at: 0)
        return box
    }()

    private let keyField = NSTextField(string: "")
    private let trackingField = NSTextField(string: "")

    private let outputView = NSTextView(frame: .zero)

    func applicationDidFinishLaunching(_ notification: Notification) {
        let repo = detectDefaultRepoPath()
        repoPathField.stringValue = repo
        hashPathField.stringValue = ""

        buildWindow()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        appendOutput("QuartzOS License Issuer (macOS app) ready.")
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    private func detectDefaultRepoPath() -> String {
        let fm = FileManager.default
        let cwd = fm.currentDirectoryPath
        if fm.fileExists(atPath: (cwd as NSString).appendingPathComponent("QuartzOS-license-issuer/issue_license.py")) {
            return cwd
        }

        var probe = URL(fileURLWithPath: Bundle.main.bundlePath)
        for _ in 0..<8 {
            probe.deleteLastPathComponent()
            let candidate = probe.path
            let script = (candidate as NSString).appendingPathComponent("QuartzOS-license-issuer/issue_license.py")
            if fm.fileExists(atPath: script) {
                return candidate
            }
        }
        return cwd
    }

    private func makeLabel(_ text: String) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        label.textColor = NSColor(calibratedWhite: 0.84, alpha: 1.0)
        return label
    }

    private func buildWindow() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1080, height: 760),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = "QuartzOS License Issuer"
        window.backgroundColor = NSColor(calibratedRed: 0.08, green: 0.11, blue: 0.16, alpha: 1.0)

        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 10
        root.translatesAutoresizingMaskIntoConstraints = false

        let topGrid = NSGridView(views: [
            [makeLabel("Repo Path"), repoPathField],
            [makeLabel("Admin Hash File (optional)"), hashPathField],
            [makeLabel("Issuer Password"), passwordField],
            [makeLabel("Owner"), ownerField],
            [makeLabel("Tier"), tierBox],
            [makeLabel("Count"), countField],
            [makeLabel("License Key"), keyField],
            [makeLabel("Tracking ID"), trackingField],
        ])
        topGrid.column(at: 0).xPlacement = .trailing
        topGrid.column(at: 1).xPlacement = .fill
        topGrid.rowSpacing = 8
        topGrid.columnSpacing = 12
        topGrid.translatesAutoresizingMaskIntoConstraints = false

        let row1 = NSStackView()
        row1.orientation = .horizontal
        row1.spacing = 8
        row1.addArrangedSubview(makeActionButton("Issue", #selector(actionIssue)))
        row1.addArrangedSubview(makeActionButton("List", #selector(actionList)))
        row1.addArrangedSubview(makeActionButton("Verify", #selector(actionVerify)))
        row1.addArrangedSubview(makeActionButton("Revoke", #selector(actionRevoke)))

        let row2 = NSStackView()
        row2.orientation = .horizontal
        row2.spacing = 8
        row2.addArrangedSubview(makeActionButton("Lookup", #selector(actionLookup)))
        row2.addArrangedSubview(makeActionButton("Deactivate QOS1/2", #selector(actionDeactivateLegacy)))
        row2.addArrangedSubview(makeActionButton("Verify Store", #selector(actionVerifyStore)))
        row2.addArrangedSubview(makeActionButton("Generate Hash", #selector(actionGenerateHash)))

        let row3 = NSStackView()
        row3.orientation = .horizontal
        row3.spacing = 8
        row3.addArrangedSubview(makeActionButton("Seal Store", #selector(actionSealStore)))
        row3.addArrangedSubview(makeActionButton("Harden Store", #selector(actionHardenStore)))
        row3.addArrangedSubview(makeActionButton("Deactivate All", #selector(actionRevokeAll)))

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false

        outputView.isEditable = false
        outputView.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        outputView.backgroundColor = NSColor(calibratedRed: 0.04, green: 0.07, blue: 0.11, alpha: 1.0)
        outputView.textColor = NSColor(calibratedWhite: 0.92, alpha: 1.0)
        scroll.documentView = outputView

        root.addArrangedSubview(topGrid)
        root.addArrangedSubview(row1)
        root.addArrangedSubview(row2)
        root.addArrangedSubview(row3)
        root.addArrangedSubview(scroll)

        let content = window.contentView!
        content.addSubview(root)

        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            root.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            root.topAnchor.constraint(equalTo: content.topAnchor, constant: 16),
            root.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -16),
            scroll.widthAnchor.constraint(equalTo: root.widthAnchor),
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 300),
            repoPathField.widthAnchor.constraint(greaterThanOrEqualToConstant: 760),
            hashPathField.widthAnchor.constraint(greaterThanOrEqualToConstant: 760),
            keyField.widthAnchor.constraint(greaterThanOrEqualToConstant: 520),
            trackingField.widthAnchor.constraint(greaterThanOrEqualToConstant: 300),
            ownerField.widthAnchor.constraint(greaterThanOrEqualToConstant: 240),
            passwordField.widthAnchor.constraint(greaterThanOrEqualToConstant: 260),
            countField.widthAnchor.constraint(greaterThanOrEqualToConstant: 100),
        ])
    }

    private func makeActionButton(_ title: String, _ action: Selector) -> NSButton {
        let button = NSButton(title: title, target: self, action: action)
        button.bezelStyle = .rounded
        return button
    }

    private func trim(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func issuerScriptPath() -> String {
        (trim(repoPathField.stringValue) as NSString).appendingPathComponent("QuartzOS-license-issuer/issue_license.py")
    }

    private func loadAdminHash() -> String? {
        let path = trim(hashPathField.stringValue)
        guard !path.isEmpty else { return nil }
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
        let value = text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }).first
        return value.map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
    }

    private func appendOutput(_ text: String) {
        let ts = ISO8601DateFormatter().string(from: Date())
        let line = "[\(ts)] \(text)\n"
        outputView.textStorage?.append(NSAttributedString(string: line))
        outputView.scrollToEndOfDocument(nil)
    }

    private func runIssuer(_ commandArgs: [String], requiresPassword: Bool, injectAdminHash: Bool = true) {
        let scriptPath = issuerScriptPath()
        guard FileManager.default.fileExists(atPath: scriptPath) else {
            appendOutput("error: issuer script not found at \(scriptPath)")
            return
        }

        if requiresPassword && trim(passwordField.stringValue).isEmpty {
            appendOutput("error: issuer password is required")
            return
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")

        var args = ["python3", scriptPath]
        if requiresPassword {
            args += ["--password-env", "QOS_ISSUER_PASSWORD"]
        }
        args += commandArgs
        process.arguments = args

        var env = ProcessInfo.processInfo.environment
        if requiresPassword {
            env["QOS_ISSUER_PASSWORD"] = trim(passwordField.stringValue)
        }
        if injectAdminHash, env["QOS_ISSUER_ADMIN_HASH"] == nil, let adminHash = loadAdminHash(), !adminHash.isEmpty {
            env["QOS_ISSUER_ADMIN_HASH"] = adminHash
        }
        process.environment = env

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        appendOutput("$ \(args.joined(separator: " "))")
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? "<non-utf8 output>"
            appendOutput(output)
            appendOutput("exit status: \(process.terminationStatus)")
        } catch {
            appendOutput("error: \(error.localizedDescription)")
        }
    }

    @objc private func actionIssue() {
        let owner = trim(ownerField.stringValue)
        guard !owner.isEmpty else {
            appendOutput("error: owner is required")
            return
        }
        let tier = trim(tierBox.stringValue)
        let count = trim(countField.stringValue).isEmpty ? "1" : trim(countField.stringValue)
        runIssuer([
            "issue", "--owner", owner, "--tier", tier, "--version", "qos3", "--count", count
        ], requiresPassword: true)
    }

    @objc private func actionList() {
        runIssuer(["list", "--show"], requiresPassword: true)
    }

    @objc private func actionVerify() {
        let key = trim(keyField.stringValue)
        guard !key.isEmpty else {
            appendOutput("error: license key is required")
            return
        }
        runIssuer(["verify", "--key", key, "--strict"], requiresPassword: false)
    }

    @objc private func actionRevoke() {
        let key = trim(keyField.stringValue)
        guard !key.isEmpty else {
            appendOutput("error: license key is required")
            return
        }
        runIssuer(["revoke", "--key", key, "--actor", "mac-app"], requiresPassword: true)
    }

    @objc private func actionRevokeAll() {
        runIssuer(["revoke-all", "--actor", "mac-app"], requiresPassword: true)
    }

    @objc private func actionDeactivateLegacy() {
        runIssuer(["deactivate-legacy", "--purge", "--actor", "mac-app"], requiresPassword: true)
    }

    @objc private func actionLookup() {
        let trackingId = trim(trackingField.stringValue)
        guard !trackingId.isEmpty else {
            appendOutput("error: tracking id is required")
            return
        }
        runIssuer(["lookup", "--tracking-id", trackingId], requiresPassword: true)
    }

    @objc private func actionVerifyStore() {
        runIssuer(["verify-store", "--require-manifest"], requiresPassword: false)
    }

    @objc private func actionSealStore() {
        runIssuer(["seal-store"], requiresPassword: true)
    }

    @objc private func actionHardenStore() {
        runIssuer(["harden-store"], requiresPassword: true)
    }

    @objc private func actionGenerateHash() {
        let outPath = trim(hashPathField.stringValue)
        guard !outPath.isEmpty else {
            appendOutput("error: admin hash output path is required")
            return
        }
        if trim(passwordField.stringValue).isEmpty {
            appendOutput("error: set issuer password first")
            return
        }

        let scriptPath = issuerScriptPath()
        guard FileManager.default.fileExists(atPath: scriptPath) else {
            appendOutput("error: issuer script not found at \(scriptPath)")
            return
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [
            "python3", scriptPath,
            "--password-env", "QOS_ISSUER_PASSWORD",
            "password-hash", "--algo", "scrypt", "--out", outPath
        ]

        var env = ProcessInfo.processInfo.environment
        env["QOS_ISSUER_PASSWORD"] = trim(passwordField.stringValue)
        process.environment = env

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        appendOutput("$ python3 issue_license.py password-hash --algo scrypt --out \(outPath)")
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? "<non-utf8 output>"
            appendOutput(output)
            appendOutput("exit status: \(process.terminationStatus)")
        } catch {
            appendOutput("error: \(error.localizedDescription)")
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
