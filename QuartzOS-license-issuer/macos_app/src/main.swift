import Cocoa
import UniformTypeIdentifiers

private struct CommandRecord {
    let title: String
    let args: [String]
    let requiresPassword: Bool
    let injectAdminHash: Bool
    let timestamp: Date
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private let keychainService = "dev.quartzos.licenseissuer"
    private let keychainAccount = "issuer_password"
    private let defaultsRepoPathKey = "issuer.repoPath"
    private let defaultsHashPathKey = "issuer.hashPath"
    private let defaultsHashOutPathKey = "issuer.hashOutPath"

    private let runner = IssuerRunner()
    private var window: NSWindow!
    private var activeProcess: Process?
    private var isRunningCommand = false
    private var queuedCommands: [() -> Void] = []
    private var commandHistory: [CommandRecord] = []

    private let tierOptions = [
        "consumer", "enterprise", "educational", "server",
        "dev_standard", "student_dev", "startup_dev", "open_lab", "oem"
    ]
    private let versionOptions = ["qos3", "qos2", "qos1"]

    // Global config controls.
    private let repoPathField = NSTextField(string: "")
    private let hashPathField = NSTextField(string: "")
    private let passwordField = NSSecureTextField(string: "")

    // Dashboard controls.
    private let issuedCountLabel = NSTextField(labelWithString: "Issued: --")
    private let activeCountLabel = NSTextField(labelWithString: "Active: --")
    private let revokedCountLabel = NSTextField(labelWithString: "Revoked: --")
    private let integrityLabel = NSTextField(labelWithString: "Integrity: --")

    // Issue tab controls.
    private let issueOwnerField = NSTextField(string: "")
    private let issueCountField = NSTextField(string: "1")
    private let issueTierBox = NSComboBox(frame: .zero)
    private let issueVersionBox = NSComboBox(frame: .zero)
    private let issueAllowLegacy = NSButton(checkboxWithTitle: "Allow legacy (qos1/qos2)", target: nil, action: nil)

    // Verify tab controls.
    private let verifyKeyField = NSTextField(string: "")
    private let verifyStrict = NSButton(checkboxWithTitle: "Strict verify", target: nil, action: nil)
    private let verifyReveal = NSButton(checkboxWithTitle: "Reveal full key", target: nil, action: nil)
    private let trackingField = NSTextField(string: "")
    private let batchVerifyInput = NSTextView(frame: .zero)

    // Revoke tab controls.
    private let revokeKeyField = NSTextField(string: "")
    private let revokeActorField = NSTextField(string: "mac-app")
    private let revokeNoteField = NSTextField(string: "")
    private let revokePurgeLegacy = NSButton(checkboxWithTitle: "Purge legacy keys from issued db", target: nil, action: nil)

    // Store tab controls.
    private let hashOutField = NSTextField(string: "")

    // Output and status controls.
    private let statusLabel = NSTextField(labelWithString: "Idle")
    private let progressIndicator = NSProgressIndicator(frame: .zero)
    private let outputView = NSTextView(frame: .zero)
    private let commandHistoryPopup = NSPopUpButton(frame: .zero, pullsDown: false)

    func applicationDidFinishLaunching(_ notification: Notification) {
        let repoPath = detectDefaultRepoPath()
        let defaults = UserDefaults.standard

        repoPathField.stringValue = defaults.string(forKey: defaultsRepoPathKey) ?? repoPath
        hashPathField.stringValue = defaults.string(forKey: defaultsHashPathKey) ?? ""
        hashOutField.stringValue = defaults.string(forKey: defaultsHashOutPathKey)
            ?? (repoPath as NSString).appendingPathComponent("build/issuer_admin_hash.txt")

        issueTierBox.addItems(withObjectValues: tierOptions)
        issueTierBox.selectItem(at: 0)
        issueVersionBox.addItems(withObjectValues: versionOptions)
        issueVersionBox.selectItem(at: 0)

        configureOutputView()
        configureBatchInputView()
        buildWindow()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        appendOutput("QuartzOS License Issuer Pro ready.")
        refreshDashboard()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationWillTerminate(_ notification: Notification) {
        let defaults = UserDefaults.standard
        defaults.set(trim(repoPathField.stringValue), forKey: defaultsRepoPathKey)
        defaults.set(trim(hashPathField.stringValue), forKey: defaultsHashPathKey)
        defaults.set(trim(hashOutField.stringValue), forKey: defaultsHashOutPathKey)
    }

    private func detectDefaultRepoPath() -> String {
        let fm = FileManager.default
        let cwd = fm.currentDirectoryPath
        if fm.fileExists(atPath: (cwd as NSString).appendingPathComponent("QuartzOS-license-issuer/issue_license.py")) {
            return cwd
        }

        var probe = URL(fileURLWithPath: Bundle.main.bundlePath)
        for _ in 0..<10 {
            probe.deleteLastPathComponent()
            let candidate = probe.path
            let script = (candidate as NSString).appendingPathComponent("QuartzOS-license-issuer/issue_license.py")
            if fm.fileExists(atPath: script) {
                return candidate
            }
        }

        return cwd
    }

    private func configureOutputView() {
        outputView.isEditable = false
        outputView.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        outputView.backgroundColor = NSColor(calibratedRed: 0.03, green: 0.06, blue: 0.10, alpha: 1.0)
        outputView.textColor = NSColor(calibratedWhite: 0.94, alpha: 1.0)
    }

    private func configureBatchInputView() {
        batchVerifyInput.isRichText = false
        batchVerifyInput.isAutomaticQuoteSubstitutionEnabled = false
        batchVerifyInput.isAutomaticTextReplacementEnabled = false
        batchVerifyInput.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        batchVerifyInput.backgroundColor = NSColor(calibratedRed: 0.05, green: 0.08, blue: 0.12, alpha: 1.0)
        batchVerifyInput.textColor = NSColor(calibratedWhite: 0.92, alpha: 1.0)
        batchVerifyInput.string = "# Paste one key per line for batch verify\n"
    }

    private func buildWindow() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1320, height: 860),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "QuartzOS License Issuer Pro"
        window.center()
        window.backgroundColor = NSColor(calibratedRed: 0.08, green: 0.11, blue: 0.16, alpha: 1.0)

        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 10
        root.translatesAutoresizingMaskIntoConstraints = false

        let content = window.contentView!
        content.addSubview(root)

        let globalConfig = buildGlobalConfigSection()
        let dashboard = buildDashboardSection()
        let split = buildMainSplitSection()

        root.addArrangedSubview(globalConfig)
        root.addArrangedSubview(dashboard)
        root.addArrangedSubview(split)

        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 14),
            root.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -14),
            root.topAnchor.constraint(equalTo: content.topAnchor, constant: 14),
            root.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -14),
            split.widthAnchor.constraint(equalTo: root.widthAnchor),
            split.heightAnchor.constraint(greaterThanOrEqualToConstant: 560),
        ])
    }

    private func buildGlobalConfigSection() -> NSView {
        let container = NSBox()
        container.title = "Environment & Auth"
        container.titlePosition = .atTop
        container.boxType = .custom
        container.borderWidth = 1
        container.borderColor = NSColor(calibratedWhite: 0.25, alpha: 1.0)
        container.fillColor = NSColor(calibratedRed: 0.11, green: 0.15, blue: 0.21, alpha: 1.0)

        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false

        let grid = NSGridView(views: [
            [makeLabel("Repo Path"), repoPathField],
            [makeLabel("Admin Hash File"), hashPathField],
            [makeLabel("Issuer Password"), passwordField],
        ])
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).xPlacement = .fill
        grid.rowSpacing = 8
        grid.columnSpacing = 12
        repoPathField.widthAnchor.constraint(greaterThanOrEqualToConstant: 880).isActive = true
        hashPathField.widthAnchor.constraint(greaterThanOrEqualToConstant: 880).isActive = true
        passwordField.widthAnchor.constraint(greaterThanOrEqualToConstant: 360).isActive = true

        let authButtons = NSStackView()
        authButtons.orientation = .horizontal
        authButtons.spacing = 8
        authButtons.addArrangedSubview(makeButton("Save Password to Keychain", #selector(actionSavePasswordToKeychain)))
        authButtons.addArrangedSubview(makeButton("Load Password", #selector(actionLoadPasswordFromKeychain)))
        authButtons.addArrangedSubview(makeButton("Clear Keychain Password", #selector(actionClearKeychainPassword)))

        stack.addArrangedSubview(grid)
        stack.addArrangedSubview(authButtons)

        container.contentView = stack
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: container.contentView!.leadingAnchor, constant: 10),
            stack.trailingAnchor.constraint(equalTo: container.contentView!.trailingAnchor, constant: -10),
            stack.topAnchor.constraint(equalTo: container.contentView!.topAnchor, constant: 10),
            stack.bottomAnchor.constraint(equalTo: container.contentView!.bottomAnchor, constant: -10),
        ])

        return container
    }

    private func buildDashboardSection() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.distribution = .fillEqually
        row.spacing = 8

        issuedCountLabel.font = NSFont.monospacedDigitSystemFont(ofSize: 13, weight: .semibold)
        activeCountLabel.font = NSFont.monospacedDigitSystemFont(ofSize: 13, weight: .semibold)
        revokedCountLabel.font = NSFont.monospacedDigitSystemFont(ofSize: 13, weight: .semibold)
        integrityLabel.font = NSFont.monospacedDigitSystemFont(ofSize: 13, weight: .semibold)

        row.addArrangedSubview(makeMetricCard("Issued", issuedCountLabel))
        row.addArrangedSubview(makeMetricCard("Active", activeCountLabel))
        row.addArrangedSubview(makeMetricCard("Revoked", revokedCountLabel))
        row.addArrangedSubview(makeMetricCard("Integrity", integrityLabel))

        return row
    }

    private func buildMainSplitSection() -> NSSplitView {
        let split = NSSplitView()
        split.isVertical = true
        split.dividerStyle = .thin
        split.translatesAutoresizingMaskIntoConstraints = false

        let tabs = buildTabsSection()
        let right = buildOutputSection()

        split.addArrangedSubview(tabs)
        split.addArrangedSubview(right)
        split.setHoldingPriority(.defaultHigh, forSubviewAt: 0)
        split.setHoldingPriority(.defaultLow, forSubviewAt: 1)
        tabs.widthAnchor.constraint(greaterThanOrEqualToConstant: 700).isActive = true

        return split
    }

    private func buildTabsSection() -> NSView {
        let tabView = NSTabView()
        tabView.tabViewType = .topTabsBezelBorder

        tabView.addTabViewItem(makeTab(title: "Issue", view: buildIssueTab()))
        tabView.addTabViewItem(makeTab(title: "Verify", view: buildVerifyTab()))
        tabView.addTabViewItem(makeTab(title: "Revocation", view: buildRevocationTab()))
        tabView.addTabViewItem(makeTab(title: "Store", view: buildStoreTab()))

        return tabView
    }

    private func makeTab(title: String, view: NSView) -> NSTabViewItem {
        let item = NSTabViewItem(identifier: title)
        item.label = title
        item.view = view
        return item
    }

    private func buildIssueTab() -> NSView {
        let box = makePaneBox()

        let grid = NSGridView(views: [
            [makeLabel("Owner"), issueOwnerField],
            [makeLabel("Tier"), issueTierBox],
            [makeLabel("Version"), issueVersionBox],
            [makeLabel("Count"), issueCountField],
        ])
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).xPlacement = .fill
        grid.rowSpacing = 8
        grid.columnSpacing = 12

        issueOwnerField.placeholderString = "Customer / Organization"
        issueOwnerField.widthAnchor.constraint(greaterThanOrEqualToConstant: 320).isActive = true
        issueCountField.widthAnchor.constraint(greaterThanOrEqualToConstant: 120).isActive = true

        let row = NSStackView()
        row.orientation = .horizontal
        row.spacing = 8
        row.addArrangedSubview(makeButton("Issue License", #selector(actionIssue)))
        row.addArrangedSubview(makeButton("Issue + Copy Keys", #selector(actionIssueAndCopyKeys)))
        row.addArrangedSubview(makeButton("Preview Command", #selector(actionPreviewIssue)))

        let content = stackInPane(box)
        content.addArrangedSubview(grid)
        content.addArrangedSubview(issueAllowLegacy)
        content.addArrangedSubview(row)
        content.addArrangedSubview(makeInfoText("Use 'Issue + Copy Keys' for instant clipboard export of generated keys."))
        return box
    }

    private func buildVerifyTab() -> NSView {
        let box = makePaneBox()

        let grid = NSGridView(views: [
            [makeLabel("License Key"), verifyKeyField],
            [makeLabel("Tracking ID"), trackingField],
        ])
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).xPlacement = .fill
        grid.rowSpacing = 8
        grid.columnSpacing = 12

        verifyKeyField.placeholderString = "QOS3-..."
        verifyKeyField.widthAnchor.constraint(greaterThanOrEqualToConstant: 500).isActive = true
        trackingField.widthAnchor.constraint(greaterThanOrEqualToConstant: 300).isActive = true

        let flags = NSStackView()
        flags.orientation = .horizontal
        flags.spacing = 10
        flags.addArrangedSubview(verifyStrict)
        flags.addArrangedSubview(verifyReveal)

        let row = NSStackView()
        row.orientation = .horizontal
        row.spacing = 8
        row.addArrangedSubview(makeButton("Verify Key", #selector(actionVerifyKey)))
        row.addArrangedSubview(makeButton("Lookup Tracking", #selector(actionLookupTracking)))

        let batchLabel = makeLabel("Batch Verify Input")
        let batchScroll = NSScrollView()
        batchScroll.hasVerticalScroller = true
        batchScroll.borderType = .bezelBorder
        batchScroll.documentView = batchVerifyInput
        batchScroll.heightAnchor.constraint(equalToConstant: 180).isActive = true

        let batchRow = NSStackView()
        batchRow.orientation = .horizontal
        batchRow.spacing = 8
        batchRow.addArrangedSubview(makeButton("Run Batch Verify", #selector(actionBatchVerify)))
        batchRow.addArrangedSubview(makeButton("Extract Keys From Text", #selector(actionExtractKeysFromBatchInput)))

        let content = stackInPane(box)
        content.addArrangedSubview(grid)
        content.addArrangedSubview(flags)
        content.addArrangedSubview(row)
        content.addArrangedSubview(batchLabel)
        content.addArrangedSubview(batchScroll)
        content.addArrangedSubview(batchRow)
        return box
    }

    private func buildRevocationTab() -> NSView {
        let box = makePaneBox()

        let grid = NSGridView(views: [
            [makeLabel("License Key"), revokeKeyField],
            [makeLabel("Actor"), revokeActorField],
            [makeLabel("Audit Note"), revokeNoteField],
        ])
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).xPlacement = .fill
        grid.rowSpacing = 8
        grid.columnSpacing = 12

        revokeKeyField.placeholderString = "QOS3-..."
        revokeKeyField.widthAnchor.constraint(greaterThanOrEqualToConstant: 500).isActive = true
        revokeActorField.widthAnchor.constraint(greaterThanOrEqualToConstant: 240).isActive = true
        revokeNoteField.widthAnchor.constraint(greaterThanOrEqualToConstant: 320).isActive = true

        let row1 = NSStackView()
        row1.orientation = .horizontal
        row1.spacing = 8
        row1.addArrangedSubview(makeButton("Revoke Key", #selector(actionRevokeKey)))
        row1.addArrangedSubview(makeButton("Unrevoke Key", #selector(actionUnrevokeKey)))

        let row2 = NSStackView()
        row2.orientation = .horizontal
        row2.spacing = 8
        row2.addArrangedSubview(makeButton("Revoke All", #selector(actionRevokeAll)))
        row2.addArrangedSubview(makeButton("Deactivate Legacy (QOS1/QOS2)", #selector(actionDeactivateLegacy)))

        let content = stackInPane(box)
        content.addArrangedSubview(grid)
        content.addArrangedSubview(revokePurgeLegacy)
        content.addArrangedSubview(row1)
        content.addArrangedSubview(row2)
        content.addArrangedSubview(makeInfoText("Revocation actions are audited and update integrity metadata."))
        return box
    }

    private func buildStoreTab() -> NSView {
        let box = makePaneBox()

        let grid = NSGridView(views: [
            [makeLabel("Password Hash Output"), hashOutField],
        ])
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).xPlacement = .fill
        grid.rowSpacing = 8
        grid.columnSpacing = 12
        hashOutField.widthAnchor.constraint(greaterThanOrEqualToConstant: 600).isActive = true

        let row1 = NSStackView()
        row1.orientation = .horizontal
        row1.spacing = 8
        row1.addArrangedSubview(makeButton("Verify Store", #selector(actionVerifyStore)))
        row1.addArrangedSubview(makeButton("Seal Store", #selector(actionSealStore)))
        row1.addArrangedSubview(makeButton("Harden Store", #selector(actionHardenStore)))

        let row2 = NSStackView()
        row2.orientation = .horizontal
        row2.spacing = 8
        row2.addArrangedSubview(makeButton("Generate Password Hash", #selector(actionGeneratePasswordHash)))
        row2.addArrangedSubview(makeButton("Refresh Dashboard", #selector(actionRefreshDashboard)))

        let content = stackInPane(box)
        content.addArrangedSubview(grid)
        content.addArrangedSubview(row1)
        content.addArrangedSubview(row2)
        content.addArrangedSubview(makeInfoText("Generate password hash only after entering a password in Issuer Password."))
        return box
    }

    private func buildOutputSection() -> NSView {
        let box = makePaneBox()

        progressIndicator.style = .spinning
        progressIndicator.controlSize = .small
        progressIndicator.isDisplayedWhenStopped = false

        statusLabel.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        statusLabel.textColor = NSColor(calibratedWhite: 0.86, alpha: 1.0)

        let statusRow = NSStackView()
        statusRow.orientation = .horizontal
        statusRow.spacing = 8
        statusRow.addArrangedSubview(progressIndicator)
        statusRow.addArrangedSubview(statusLabel)
        statusRow.addArrangedSubview(makeButton("Stop Active Command", #selector(actionStopActiveCommand)))

        let controlsRow = NSStackView()
        controlsRow.orientation = .horizontal
        controlsRow.spacing = 8
        controlsRow.addArrangedSubview(makeButton("Save Output Log", #selector(actionSaveOutputLog)))
        controlsRow.addArrangedSubview(makeButton("Clear Output", #selector(actionClearOutput)))

        let outputScroll = NSScrollView()
        outputScroll.hasVerticalScroller = true
        outputScroll.borderType = .bezelBorder
        outputScroll.documentView = outputView
        outputScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 440).isActive = true

        commandHistoryPopup.widthAnchor.constraint(greaterThanOrEqualToConstant: 360).isActive = true

        let historyRow = NSStackView()
        historyRow.orientation = .horizontal
        historyRow.spacing = 8
        historyRow.addArrangedSubview(makeLabel("Recent Commands"))
        historyRow.addArrangedSubview(commandHistoryPopup)
        historyRow.addArrangedSubview(makeButton("Rerun Selected", #selector(actionRerunSelectedCommand)))

        let content = stackInPane(box)
        content.addArrangedSubview(statusRow)
        content.addArrangedSubview(controlsRow)
        content.addArrangedSubview(outputScroll)
        content.addArrangedSubview(historyRow)
        return box
    }

    private func makePaneBox() -> NSBox {
        let box = NSBox()
        box.boxType = .custom
        box.borderWidth = 1
        box.borderColor = NSColor(calibratedWhite: 0.25, alpha: 1.0)
        box.fillColor = NSColor(calibratedRed: 0.10, green: 0.14, blue: 0.20, alpha: 1.0)
        return box
    }

    private func stackInPane(_ box: NSBox) -> NSStackView {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        box.contentView = stack

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: box.contentView!.leadingAnchor, constant: 10),
            stack.trailingAnchor.constraint(equalTo: box.contentView!.trailingAnchor, constant: -10),
            stack.topAnchor.constraint(equalTo: box.contentView!.topAnchor, constant: 10),
            stack.bottomAnchor.constraint(equalTo: box.contentView!.bottomAnchor, constant: -10),
        ])
        return stack
    }

    private func makeMetricCard(_ title: String, _ valueLabel: NSTextField) -> NSView {
        let card = NSBox()
        card.boxType = .custom
        card.borderWidth = 1
        card.borderColor = NSColor(calibratedWhite: 0.24, alpha: 1.0)
        card.fillColor = NSColor(calibratedRed: 0.10, green: 0.14, blue: 0.20, alpha: 1.0)

        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 2
        stack.translatesAutoresizingMaskIntoConstraints = false

        let titleLabel = makeLabel(title)
        titleLabel.font = NSFont.systemFont(ofSize: 11, weight: .semibold)
        valueLabel.textColor = NSColor(calibratedWhite: 0.95, alpha: 1.0)

        stack.addArrangedSubview(titleLabel)
        stack.addArrangedSubview(valueLabel)

        card.contentView = stack
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: card.contentView!.leadingAnchor, constant: 8),
            stack.trailingAnchor.constraint(equalTo: card.contentView!.trailingAnchor, constant: -8),
            stack.topAnchor.constraint(equalTo: card.contentView!.topAnchor, constant: 6),
            stack.bottomAnchor.constraint(equalTo: card.contentView!.bottomAnchor, constant: -6),
        ])

        return card
    }

    private func makeLabel(_ text: String) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        label.textColor = NSColor(calibratedWhite: 0.86, alpha: 1.0)
        return label
    }

    private func makeInfoText(_ text: String) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = NSFont.systemFont(ofSize: 11, weight: .regular)
        label.textColor = NSColor(calibratedWhite: 0.72, alpha: 1.0)
        return label
    }

    private func makeButton(_ title: String, _ action: Selector) -> NSButton {
        let button = NSButton(title: title, target: self, action: action)
        button.bezelStyle = .rounded
        return button
    }

    private func trim(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func appendOutput(_ text: String, includeTimestamp: Bool = true) {
        let sanitized = text.replacingOccurrences(of: "\r\n", with: "\n")
        let line: String
        if includeTimestamp {
            let stamp = ISO8601DateFormatter().string(from: Date())
            line = "[\(stamp)] \(sanitized)"
        } else {
            line = sanitized
        }

        outputView.textStorage?.append(NSAttributedString(string: line.hasSuffix("\n") ? line : line + "\n"))
        outputView.scrollToEndOfDocument(nil)
    }

    private func setRunning(_ running: Bool, status: String) {
        isRunningCommand = running
        statusLabel.stringValue = status
        if running {
            progressIndicator.startAnimation(nil)
        } else {
            progressIndicator.stopAnimation(nil)
        }
    }

    private func enqueueCommand(_ work: @escaping () -> Void) {
        if isRunningCommand {
            queuedCommands.append(work)
            return
        }
        work()
    }

    private func runNextQueuedCommandIfNeeded() {
        guard !isRunningCommand, !queuedCommands.isEmpty else {
            return
        }
        let next = queuedCommands.removeFirst()
        next()
    }

    private func issuerScriptPath() -> String {
        (trim(repoPathField.stringValue) as NSString).appendingPathComponent("QuartzOS-license-issuer/issue_license.py")
    }

    private func loadAdminHashFromFile() -> String? {
        let path = trim(hashPathField.stringValue)
        guard !path.isEmpty,
              let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            return nil
        }
        return text
            .split(whereSeparator: { $0 == "\n" || $0 == "\r" })
            .first
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
    }

    private func issuerPasswordOrNil() -> String? {
        let pwd = trim(passwordField.stringValue)
        return pwd.isEmpty ? nil : pwd
    }

    private func issueCommandArgs(showKeys: Bool) -> [String]? {
        let owner = trim(issueOwnerField.stringValue)
        if owner.isEmpty {
            appendOutput("error: owner is required")
            return nil
        }

        let tier = trim(issueTierBox.stringValue).isEmpty ? "consumer" : trim(issueTierBox.stringValue)
        let version = trim(issueVersionBox.stringValue).isEmpty ? "qos3" : trim(issueVersionBox.stringValue)
        let count = trim(issueCountField.stringValue).isEmpty ? "1" : trim(issueCountField.stringValue)

        var args = [
            "issue",
            "--owner", owner,
            "--tier", tier,
            "--version", version,
            "--count", count,
        ]
        if issueAllowLegacy.state == .on {
            args.append("--allow-legacy")
        }
        if showKeys {
            args.append("--show-keys")
        }
        return args
    }

    private func recordCommand(_ command: CommandRecord) {
        commandHistory.insert(command, at: 0)
        if commandHistory.count > 25 {
            commandHistory.removeLast(commandHistory.count - 25)
        }

        commandHistoryPopup.removeAllItems()
        for item in commandHistory {
            let f = DateFormatter()
            f.dateFormat = "HH:mm:ss"
            let ts = f.string(from: item.timestamp)
            commandHistoryPopup.addItem(withTitle: "[\(ts)] \(item.title)")
        }
    }

    private func launchCommand(
        title: String,
        args: [String],
        requiresPassword: Bool,
        injectAdminHash: Bool = true,
        recordInHistory: Bool = true,
        onComplete: ((IssuerRunResult) -> Void)? = nil
    ) {
        enqueueCommand { [weak self] in
            guard let self else { return }

            let scriptPath = self.issuerScriptPath()
            let password = self.issuerPasswordOrNil()
            if requiresPassword && password == nil {
                self.appendOutput("error: issuer password is required")
                return
            }

            let request = IssuerRunRequest(
                scriptPath: scriptPath,
                commandArgs: args,
                password: password,
                passwordEnv: "QOS_ISSUER_PASSWORD",
                adminHash: self.loadAdminHashFromFile(),
                injectAdminHash: injectAdminHash
            )

            self.setRunning(true, status: "Running: \(title)")
            self.appendOutput("$ python3 issue_license.py \(args.joined(separator: " "))")

            if recordInHistory {
                self.recordCommand(
                    CommandRecord(
                        title: title,
                        args: args,
                        requiresPassword: requiresPassword,
                        injectAdminHash: injectAdminHash,
                        timestamp: Date()
                    )
                )
            }

            do {
                self.activeProcess = try self.runner.run(
                    request: request,
                    onChunk: { [weak self] chunk in
                        guard let self else { return }
                        self.appendOutput(chunk, includeTimestamp: false)
                    },
                    onComplete: { [weak self] result in
                        guard let self else { return }
                        self.activeProcess = nil
                        self.appendOutput("exit status: \(result.exitCode)")
                        self.setRunning(false, status: "Idle")
                        onComplete?(result)
                        self.runNextQueuedCommandIfNeeded()
                    }
                )
            } catch {
                self.activeProcess = nil
                self.appendOutput("error: \(error.localizedDescription)")
                self.setRunning(false, status: "Idle")
                self.runNextQueuedCommandIfNeeded()
            }
        }
    }

    private func refreshDashboard() {
        launchCommand(
            title: "Dashboard: list",
            args: ["list"],
            requiresPassword: true,
            recordInHistory: false
        ) { [weak self] result in
            guard let self else { return }
            self.updateDashboardCounts(from: result.output)

            self.launchCommand(
                title: "Dashboard: verify-store",
                args: ["verify-store", "--require-manifest"],
                requiresPassword: false,
                recordInHistory: false
            ) { [weak self] verifyResult in
                self?.updateDashboardIntegrity(from: verifyResult.output, exitCode: verifyResult.exitCode)
            }
        }
    }

    private func updateDashboardCounts(from output: String) {
        if let issued = parseInteger(after: "total issued keys:", in: output) {
            issuedCountLabel.stringValue = "Issued: \(issued)"
        }
        if let active = parseInteger(after: "active keys:", in: output) {
            activeCountLabel.stringValue = "Active: \(active)"
        }
        if let revoked = parseInteger(after: "revoked keys:", in: output) {
            revokedCountLabel.stringValue = "Revoked: \(revoked)"
        }
    }

    private func updateDashboardIntegrity(from output: String, exitCode: Int32) {
        if output.lowercased().contains("integrity manifest: ok") && exitCode == 0 {
            integrityLabel.stringValue = "Integrity: ok"
            integrityLabel.textColor = NSColor.systemGreen
        } else {
            integrityLabel.stringValue = "Integrity: issues"
            integrityLabel.textColor = NSColor.systemRed
        }
    }

    private func parseInteger(after prefix: String, in output: String) -> Int? {
        for line in output.split(separator: "\n") {
            let text = line.trimmingCharacters(in: .whitespaces)
            if !text.lowercased().hasPrefix(prefix.lowercased()) {
                continue
            }
            let valueText = text.dropFirst(prefix.count).trimmingCharacters(in: .whitespaces)
            return Int(valueText)
        }
        return nil
    }

    private func extractLicenseKeys(from text: String) -> [String] {
        let patterns = [
            "QOS3-[A-F0-9]{8}-[A-F0-9]{2}-[A-F0-9]{2}-[A-F0-9]{8}-[A-F0-9]{24}",
            "QOS2-[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{8}-[A-F0-9]{16}",
            "QOS1-[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{8}",
        ]

        var keys: [String] = []
        var seen: Set<String> = []
        for pattern in patterns {
            guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else {
                continue
            }
            let nsText = text as NSString
            let matches = regex.matches(in: text, options: [], range: NSRange(location: 0, length: nsText.length))
            for match in matches {
                let key = nsText.substring(with: match.range)
                if seen.insert(key).inserted {
                    keys.append(key)
                }
            }
        }
        return keys
    }

    private func copyKeysToClipboard(_ keys: [String]) {
        guard !keys.isEmpty else {
            return
        }
        let paste = NSPasteboard.general
        paste.clearContents()
        paste.setString(keys.joined(separator: "\n"), forType: .string)
    }

    private func commandPreview(_ args: [String]) {
        appendOutput("preview: python3 issue_license.py \(args.joined(separator: " "))")
    }

    @objc private func actionIssue() {
        guard let args = issueCommandArgs(showKeys: false) else {
            return
        }
        launchCommand(title: "Issue", args: args, requiresPassword: true) { [weak self] _ in
            self?.refreshDashboard()
        }
    }

    @objc private func actionIssueAndCopyKeys() {
        guard let args = issueCommandArgs(showKeys: true) else {
            return
        }
        launchCommand(title: "Issue + Copy", args: args, requiresPassword: true) { [weak self] result in
            guard let self else { return }
            let keys = self.extractLicenseKeys(from: result.output)
            self.copyKeysToClipboard(keys)
            self.appendOutput("copied \(keys.count) key(s) to clipboard")
            self.refreshDashboard()
        }
    }

    @objc private func actionPreviewIssue() {
        guard let args = issueCommandArgs(showKeys: false) else {
            return
        }
        commandPreview(args)
    }

    @objc private func actionVerifyKey() {
        let key = trim(verifyKeyField.stringValue)
        if key.isEmpty {
            appendOutput("error: license key is required")
            return
        }

        var args = ["verify", "--key", key]
        if verifyStrict.state == .on {
            args.append("--strict")
        }
        if verifyReveal.state == .on {
            args.append("--reveal")
        }

        launchCommand(title: "Verify", args: args, requiresPassword: false)
    }

    @objc private func actionLookupTracking() {
        let tracking = trim(trackingField.stringValue)
        if tracking.isEmpty {
            appendOutput("error: tracking id is required")
            return
        }

        var args = ["lookup", "--tracking-id", tracking]
        if verifyReveal.state == .on {
            args.append("--reveal")
        }
        launchCommand(title: "Lookup", args: args, requiresPassword: true)
    }

    @objc private func actionBatchVerify() {
        let keys = extractLicenseKeys(from: batchVerifyInput.string)
        if keys.isEmpty {
            appendOutput("batch verify: no valid keys found")
            return
        }

        appendOutput("batch verify: \(keys.count) keys queued")
        var index = 0
        var success = 0
        var failed = 0

        func runNext() {
            if index >= keys.count {
                appendOutput("batch verify completed: success=\(success) failed=\(failed)")
                return
            }

            let key = keys[index]
            index += 1
            var args = ["verify", "--key", key]
            if verifyStrict.state == .on {
                args.append("--strict")
            }

            launchCommand(
                title: "Batch Verify \(index)/\(keys.count)",
                args: args,
                requiresPassword: false,
                recordInHistory: false
            ) { result in
                if result.exitCode == 0 {
                    success += 1
                } else {
                    failed += 1
                }
                runNext()
            }
        }

        runNext()
    }

    @objc private func actionExtractKeysFromBatchInput() {
        let keys = extractLicenseKeys(from: batchVerifyInput.string)
        appendOutput("batch input parser found \(keys.count) key(s)")
        if !keys.isEmpty {
            copyKeysToClipboard(keys)
            appendOutput("copied parsed keys to clipboard")
        }
    }

    @objc private func actionRevokeKey() {
        let key = trim(revokeKeyField.stringValue)
        if key.isEmpty {
            appendOutput("error: license key is required")
            return
        }

        var args = ["revoke", "--key", key, "--actor", trim(revokeActorField.stringValue).isEmpty ? "mac-app" : trim(revokeActorField.stringValue)]
        let note = trim(revokeNoteField.stringValue)
        if !note.isEmpty {
            args += ["--note", note]
        }

        launchCommand(title: "Revoke", args: args, requiresPassword: true) { [weak self] _ in
            self?.refreshDashboard()
        }
    }

    @objc private func actionUnrevokeKey() {
        let key = trim(revokeKeyField.stringValue)
        if key.isEmpty {
            appendOutput("error: license key is required")
            return
        }

        var args = ["unrevoke", "--key", key, "--actor", trim(revokeActorField.stringValue).isEmpty ? "mac-app" : trim(revokeActorField.stringValue)]
        let note = trim(revokeNoteField.stringValue)
        if !note.isEmpty {
            args += ["--note", note]
        }

        launchCommand(title: "Unrevoke", args: args, requiresPassword: true) { [weak self] _ in
            self?.refreshDashboard()
        }
    }

    @objc private func actionRevokeAll() {
        var args = ["revoke-all", "--actor", trim(revokeActorField.stringValue).isEmpty ? "mac-app" : trim(revokeActorField.stringValue)]
        let note = trim(revokeNoteField.stringValue)
        if !note.isEmpty {
            args += ["--note", note]
        }

        launchCommand(title: "Revoke All", args: args, requiresPassword: true) { [weak self] _ in
            self?.refreshDashboard()
        }
    }

    @objc private func actionDeactivateLegacy() {
        var args = ["deactivate-legacy", "--actor", trim(revokeActorField.stringValue).isEmpty ? "mac-app" : trim(revokeActorField.stringValue)]
        if revokePurgeLegacy.state == .on {
            args.append("--purge")
        }

        launchCommand(title: "Deactivate Legacy", args: args, requiresPassword: true) { [weak self] _ in
            self?.refreshDashboard()
        }
    }

    @objc private func actionVerifyStore() {
        launchCommand(title: "Verify Store", args: ["verify-store", "--require-manifest"], requiresPassword: false) { [weak self] result in
            self?.updateDashboardIntegrity(from: result.output, exitCode: result.exitCode)
        }
    }

    @objc private func actionSealStore() {
        launchCommand(title: "Seal Store", args: ["seal-store"], requiresPassword: true) { [weak self] _ in
            self?.refreshDashboard()
        }
    }

    @objc private func actionHardenStore() {
        launchCommand(title: "Harden Store", args: ["harden-store"], requiresPassword: true) { [weak self] _ in
            self?.refreshDashboard()
        }
    }

    @objc private func actionGeneratePasswordHash() {
        let out = trim(hashOutField.stringValue)
        if out.isEmpty {
            appendOutput("error: hash output path is required")
            return
        }

        if issuerPasswordOrNil() == nil {
            appendOutput("error: issuer password is required to generate password hash")
            return
        }

        launchCommand(
            title: "Generate Password Hash",
            args: ["password-hash", "--algo", "scrypt", "--out", out],
            requiresPassword: true,
            injectAdminHash: false
        )
    }

    @objc private func actionRefreshDashboard() {
        refreshDashboard()
    }

    @objc private func actionSavePasswordToKeychain() {
        guard let password = issuerPasswordOrNil() else {
            appendOutput("error: enter issuer password before saving to keychain")
            return
        }

        do {
            try KeychainStore.savePassword(password, service: keychainService, account: keychainAccount)
            appendOutput("keychain: password saved")
        } catch {
            appendOutput("keychain save failed: \(error.localizedDescription)")
        }
    }

    @objc private func actionLoadPasswordFromKeychain() {
        do {
            if let password = try KeychainStore.loadPassword(service: keychainService, account: keychainAccount) {
                passwordField.stringValue = password
                appendOutput("keychain: password loaded into field")
            } else {
                appendOutput("keychain: no saved password")
            }
        } catch {
            appendOutput("keychain load failed: \(error.localizedDescription)")
        }
    }

    @objc private func actionClearKeychainPassword() {
        do {
            try KeychainStore.deletePassword(service: keychainService, account: keychainAccount)
            passwordField.stringValue = ""
            appendOutput("keychain: saved password deleted")
        } catch {
            appendOutput("keychain delete failed: \(error.localizedDescription)")
        }
    }

    @objc private func actionStopActiveCommand() {
        guard let process = activeProcess else {
            appendOutput("no active command to stop")
            return
        }
        process.terminate()
        appendOutput("active command terminated")
    }

    @objc private func actionSaveOutputLog() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "issuer-log-\(Int(Date().timeIntervalSince1970)).txt"
        panel.allowedContentTypes = [.plainText]

        panel.beginSheetModal(for: window) { [weak self] response in
            guard let self, response == .OK, let url = panel.url else {
                return
            }
            let text = self.outputView.string
            do {
                try text.write(to: url, atomically: true, encoding: .utf8)
                self.appendOutput("saved output log: \(url.path)")
            } catch {
                self.appendOutput("failed to save output log: \(error.localizedDescription)")
            }
        }
    }

    @objc private func actionClearOutput() {
        outputView.string = ""
        appendOutput("output cleared")
    }

    @objc private func actionRerunSelectedCommand() {
        let index = commandHistoryPopup.indexOfSelectedItem
        if index < 0 || index >= commandHistory.count {
            appendOutput("no command selected")
            return
        }

        let cmd = commandHistory[index]
        launchCommand(
            title: "Rerun: \(cmd.title)",
            args: cmd.args,
            requiresPassword: cmd.requiresPassword,
            injectAdminHash: cmd.injectAdminHash,
            recordInHistory: false
        )
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
