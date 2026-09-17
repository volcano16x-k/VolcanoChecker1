import Foundation
import Combine

public struct CrashReportResult: Identifiable {
    public let id = UUID()
    public let fileName: String
    public let path: String
    public let matchedIndicators: [String]
    public let status: SecurityStatus

    public init(fileName: String, path: String, matchedIndicators: [String], status: SecurityStatus) {
        self.fileName = fileName
        self.path = path
        self.matchedIndicators = matchedIndicators
        self.status = status
    }
}

public final class CrashReportScanner: ObservableObject {
    @Published public var results: [CrashReportResult] = []
    @Published public var isScanning = false

    private let dangerousIndicators = [
        "filza", "filzajailed", "filzaslop", "filzaescaped", "filzahelper",
        "gbox", "3105", "h5gg", "sileo", "roothide", "trollstore",
        "trollstore lite", "patcher", "mobilehousearrest", "stack+", "stackpanel",
        "newterm", "newterm2", "frida", "cycript", "debugserver", "ellekit",
        "libhooker", "substrate", "substitute", "dopamine", "unc0ver",
        "checkra1n", "palera1n", "jailbreak", "esign", "sideload", "external", "vip"
    ]

    private let allowedExtensions = ["ips", "crash", "json", "txt", "log"]

    public init() {}

    public func scanCrashReports(directoryPath: String, completion: (() -> Void)? = nil) {
        DispatchQueue.main.async {
            self.results.removeAll()
            self.isScanning = true
        }

        let root = URL(fileURLWithPath: directoryPath)

        DispatchQueue.global(qos: .userInitiated).async {
            var output: [CrashReportResult] = []

            if let enumerator = FileManager.default.enumerator(
                at: root,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) {
                for case let url as URL in enumerator {
                    guard self.allowedExtensions.contains(url.pathExtension.lowercased()) else { continue }
                    guard let data = try? Data(contentsOf: url) else { continue }

                    let text = String(data: data, encoding: .utf8) ?? ""
                    let lower = text.lowercased()
                    let matches = Array(Set(self.dangerousIndicators.filter { lower.contains($0) })).sorted()

                    output.append(
                        CrashReportResult(
                            fileName: url.lastPathComponent,
                            path: url.path,
                            matchedIndicators: matches,
                            status: matches.isEmpty ? .clean : .suspicious
                        )
                    )
                }
            }

            output.sort { $0.status.priority > $1.status.priority }

            DispatchQueue.main.async {
                self.results = output
                self.isScanning = false
                completion?()
            }
        }
    }
}
