import Foundation
import Combine

public struct GroupedPrivacyItem: Identifiable {
    public let id = UUID()
    public let appName: String
    public let bundleID: String
    public let status: SecurityStatus
    public let reason: String
    public let timestamps: [String]
    public let accessedCategories: [String]

    public init(appName: String, bundleID: String, status: SecurityStatus, reason: String, timestamps: [String], accessedCategories: [String]) {
        self.appName = appName
        self.bundleID = bundleID
        self.status = status
        self.reason = reason
        self.timestamps = timestamps
        self.accessedCategories = accessedCategories
    }
}

public final class AppPrivacyAnalyzer: ObservableObject {
    @Published public var groupedItems: [GroupedPrivacyItem] = []
    @Published public var isProcessing = false

    private let dangerousTerms = [
        "filza", "filzajailed", "filzaslop", "trollstore", "trollstore lite", "esign",
        "gbox", "stack+", "stackpanel", "h5gg", "sileo", "jailbreak", "dopamine",
        "unc0ver", "checkra1n", "palera1n", "frida", "cycript", "ellekit",
        "libhooker", "substrate", "substitute", "external", "vip", "ios"
    ]

    private let warningTerms = [
        "proxy", "vpn", "mitmproxy", "shadowrocket", "surge", "quantumult", "loon",
        "stash", "clash", "sing-box", "singbox", "v2ray", "xray"
    ]

    public init() {}

    public func analyzeAndGroup(rawEntries: [PrivacyRawEntry]) {
        DispatchQueue.main.async { self.isProcessing = true }

        DispatchQueue.global(qos: .userInitiated).async {
            struct Temp {
                var status: SecurityStatus
                var reason: String
                var timestamps: [String]
                var categories: Set<String>
                var bundleID: String
            }

            var map: [String: Temp] = [:]

            for entry in rawEntries {
                let rawBundle = entry.accessor?.identifier ?? entry.identifier ?? "Unknown App"
                let normalized = rawBundle.trimmingCharacters(in: .whitespacesAndNewlines)
                let appName = normalized.isEmpty ? "Unknown App" : (normalized as NSString).lastPathComponent
                let lower = normalized.lowercased()
                let timestamp = entry.timeStamp ?? "غير مؤرخ"
                let category = entry.category ?? "General Access"

                var status: SecurityStatus = .clean
                var reason = "سلوك عادي في استخدام الصلاحيات"

                if let term = self.dangerousTerms.first(where: { lower.contains($0) }) {
                    status = .suspicious
                    reason = "مؤشر مشبوه: \(term)"
                } else if let term = self.warningTerms.first(where: { lower.contains($0) }) {
                    status = .warning
                    reason = "مؤشر يحتاج مراجعة: \(term)"
                } else if normalized == "Unknown App" || entry.accessor?.identifierType?.lowercased() == "unknown" {
                    status = .warning
                    reason = "Bundle ID غير معروف يحتاج مراجعة"
                }

                if var existing = map[appName] {
                    existing.timestamps.append(timestamp)
                    existing.categories.insert(category)
                    if status.priority > existing.status.priority {
                        existing.status = status
                        existing.reason = reason
                    }
                    map[appName] = existing
                } else {
                    map[appName] = Temp(status: status, reason: reason, timestamps: [timestamp], categories: [category], bundleID: normalized)
                }
            }

            let list = map.map { name, data in
                GroupedPrivacyItem(
                    appName: name,
                    bundleID: data.bundleID,
                    status: data.status,
                    reason: data.reason,
                    timestamps: Array(Set(data.timestamps)).sorted(),
                    accessedCategories: Array(data.categories).sorted()
                )
            }

            DispatchQueue.main.async {
                self.groupedItems = list.sorted { $0.status.priority > $1.status.priority }
                self.isProcessing = false
            }
        }
    }
}
