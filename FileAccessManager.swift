import Foundation
import Combine

public struct ScanFileResult: Identifiable {
    public let id = UUID()
    public let name: String
    public let path: String
    public let reason: String
    public let status: SecurityStatus

    public init(name: String, path: String, reason: String, status: SecurityStatus) {
        self.name = name
        self.path = path
        self.reason = reason
        self.status = status
    }
}

public final class FileAccessManager: ObservableObject {
    public static let shared = FileAccessManager()

    @Published public var scannedFiles: [ScanFileResult] = []
    @Published public var isScanning = false

    private let suspiciousNames = [
        "drag", "obb", "chest", "neck", "panel", "menu", "inject"
    ]

    private let suspiciousExtensions = [
        "ipa", "tipa", "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "tgz"
    ]

    private init() {}

    public func runGeneralScan(targetDirectory: String, completion: (() -> Void)? = nil) {
        let root = URL(fileURLWithPath: targetDirectory)

        DispatchQueue.main.async {
            self.scannedFiles.removeAll()
            self.isScanning = true
        }

        DispatchQueue.global(qos: .userInitiated).async {
            var results: [ScanFileResult] = []
            let keys: [URLResourceKey] = [.isDirectoryKey, .isRegularFileKey]

            if let enumerator = FileManager.default.enumerator(
                at: root,
                includingPropertiesForKeys: keys,
                options: [.skipsHiddenFiles]
            ) {
                for case let url as URL in enumerator {
                    let name = url.lastPathComponent.lowercased()
                    let ext = url.pathExtension.lowercased()
                    var reason: String?
                    var status: SecurityStatus = .warning

                    for keyword in self.suspiciousNames where name.contains(keyword) {
                        reason = "اسم مشبوه: \(keyword)"
                        status = .suspicious
                        break
                    }

                    if reason == nil, !ext.isEmpty, self.suspiciousExtensions.contains(ext) {
                        reason = "امتداد مشبوه: .\(ext)"
                        status = ext == "ipa" || ext == "tipa" ? .suspicious : .warning
                    }

                    if let reason {
                        results.append(
                            ScanFileResult(
                                name: url.lastPathComponent,
                                path: url.path,
                                reason: reason,
                                status: status
                            )
                        )
                    }
                }
            }

            results.sort { $0.status.priority > $1.status.priority }

            DispatchQueue.main.async {
                self.scannedFiles = results
                self.isScanning = false
                completion?()
            }
        }
    }
}
