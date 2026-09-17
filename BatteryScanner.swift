import Foundation
import Combine

public struct BatteryResult: Identifiable {
    public let id = UUID()
    public let appName: String
    public let bundleID: String
    public let eventDescription: String
    public let status: SecurityStatus

    public init(appName: String, bundleID: String, eventDescription: String, status: SecurityStatus) {
        self.appName = appName
        self.bundleID = bundleID
        self.eventDescription = eventDescription
        self.status = status
    }
}

public final class BatteryScanner: ObservableObject {
    @Published public var detectedApps: [BatteryResult] = []
    @Published public var isScanning = false

    private let dangerousTerms = [
        "filza", "filzajailed", "filzaslop", "filzaescaped", "filzahelper", "gbox",
        "stack+", "stackpanel", "h5gg", "sileo", "roothide", "trollstore",
        "trollstore lite", "patcher", "frida", "cycript", "debugserver", "newterm",
        "newterm2", "dopamine", "jailbreak", "esign", "external", "vip",
        "libhooker", "substrate", "substitute", "ellekit", "checkra1n", "unc0ver",
        "palera1n", "mobilehousearrest"
    ]

    public init() {}

    public func scanBatteryAndProfileData(baseDirectory: String, completion: (() -> Void)? = nil) {
        DispatchQueue.main.async {
            self.detectedApps.removeAll()
            self.isScanning = true
        }

        let root = URL(fileURLWithPath: baseDirectory)

        DispatchQueue.global(qos: .userInitiated).async {
            var results: [BatteryResult] = []
            let files = self.collectFiles(from: root)

            for url in files {
                let name = url.lastPathComponent.lowercased()

                guard name == "currentpowerlog.plsql" ||
                      name == "currentpowerlog.plsql-shm" ||
                      name == "currentpowerlog.plsql-wal" ||
                      name.contains("powerlog") ||
                      name.contains("batterylife") else { continue }

                results.append(contentsOf: self.analyzePowerlogFile(url))
            }

            results = self.deduplicate(results)
            results.sort {
                if $0.status.priority != $1.status.priority {
                    return $0.status.priority > $1.status.priority
                }
                return $0.appName.localizedCaseInsensitiveCompare($1.appName) == .orderedAscending
            }

            DispatchQueue.main.async {
                self.detectedApps = results
                self.isScanning = false
                completion?()
            }
        }
    }

    private func collectFiles(from root: URL) -> [URL] {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: root.path, isDirectory: &isDirectory) else { return [] }
        if !isDirectory.boolValue { return [root] }
        guard let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil, options: []) else { return [] }
        return enumerator.compactMap { $0 as? URL }
    }

    private func analyzePowerlogFile(_ url: URL) -> [BatteryResult] {
        guard let data = try? Data(contentsOf: url) else {
            return [BatteryResult(appName: url.lastPathComponent, bundleID: "", eventDescription: "🟡 تعذر قراءة ملف Powerlog", status: .warning)]
        }

        let text = extractReadableStrings(from: data)
        let lower = text.lowercased()
        var output: [BatteryResult] = []

        let indicators = dangerousTerms.filter { lower.contains($0) }
        let bundleIDs = extractBundleIDs(from: text)

        if !indicators.isEmpty {
            output.append(BatteryResult(
                appName: url.lastPathComponent,
                bundleID: bundleIDs.first ?? "",
                eventDescription: "🔴 مؤشرات مشبوهة: \(Array(Set(indicators)).sorted().joined(separator: ", "))",
                status: .suspicious
            ))
        }

        for bundleID in bundleIDs.prefix(100) {
            let id = bundleID.lowercased()
            let apple = id.hasPrefix("com.apple.")
            let heuristic = id.contains("external") || id.contains("vip") || id.contains("ios")

            if heuristic {
                output.append(BatteryResult(
                    appName: lastComponent(bundleID),
                    bundleID: bundleID,
                    eventDescription: "🔴 مؤشر مشبوه في Bundle ID (heuristic)",
                    status: .suspicious
                ))
            } else if apple {
                output.append(BatteryResult(
                    appName: lastComponent(bundleID),
                    bundleID: bundleID,
                    eventDescription: " خدمة/تطبيق Apple ظاهر في Powerlog",
                    status: .clean
                ))
            } else {
                output.append(BatteryResult(
                    appName: lastComponent(bundleID),
                    bundleID: bundleID,
                    eventDescription: "📱 نشاط تطبيق ظاهر في Powerlog",
                    status: .clean
                ))
            }
        }

        if lower.contains("deleted") || lower.contains("uninstalled") || lower.contains("uninstall") || lower.contains("removed") {
            output.append(BatteryResult(
                appName: "Deleted App Event",
                bundleID: bundleIDs.first ?? "",
                eventDescription: "🗑️ مؤشر حذف/إزالة تطبيق داخل البيانات المقروءة",
                status: .warning
            ))
        }

        if lower.contains("authentication") || lower.contains("authenticated") || lower.contains("lastlogin") || lower.contains("login") {
            output.append(BatteryResult(
                appName: "Authentication",
                bundleID: bundleIDs.first ?? "",
                eventDescription: "🔐 نشاط Authentication/Login ظاهر في البيانات",
                status: .warning
            ))
        }

        if output.isEmpty {
            output.append(BatteryResult(
                appName: url.lastPathComponent,
                bundleID: "Powerlog",
                eventDescription: "🟡 تم فتح الملف وقراءة البيانات القابلة للاستخراج، لكن لم تظهر مؤشرات أو Bundle IDs قابلة للتصنيف",
                status: .warning
            ))
        }

        return output
    }

    // SQLite is a binary format. This extracts printable strings from the imported
    // database, which is safe and does not require private iOS access or SQLite3 linkage.
    private func extractReadableStrings(from data: Data) -> String {
        var output = ""
        var current = ""

        for byte in data {
            if byte >= 32 && byte <= 126 {
                current.append(Character(UnicodeScalar(byte)))
            } else {
                if current.count >= 4 {
                    output.append(current)
                    output.append("\n")
                }
                current.removeAll(keepingCapacity: true)
            }
        }

        if current.count >= 4 { output.append(current) }
        return output
    }

    private func extractBundleIDs(from text: String) -> [String] {
        let pattern = #"\b[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]{2,}\b"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        let matches = regex.matches(in: text, range: range)
        var values: [String] = []

        for match in matches {
            guard let r = Range(match.range, in: text) else { continue }
            let value = String(text[r])
            guard value.count >= 6 else { continue }
            if !values.contains(where: { $0.caseInsensitiveCompare(value) == .orderedSame }) {
                values.append(value)
            }
        }
        return values
    }

    private func lastComponent(_ value: String) -> String {
        String(value.split(separator: ".").last ?? Substring(value))
    }

    private func deduplicate(_ values: [BatteryResult]) -> [BatteryResult] {
        var seen = Set<String>()
        var output: [BatteryResult] = []
        for value in values {
            let key = "\(value.appName)|\(value.bundleID)|\(value.eventDescription)"
            if seen.insert(key).inserted { output.append(value) }
        }
        return output
    }
}
