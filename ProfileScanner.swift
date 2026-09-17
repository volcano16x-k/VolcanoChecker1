import Foundation
import Combine

public struct ProfileResult: Identifiable {
    public let id = UUID()
    public let fileName: String
    public let path: String
    public let indicators: [String]
    public let status: SecurityStatus

    public init(fileName: String, path: String, indicators: [String], status: SecurityStatus) {
        self.fileName = fileName
        self.path = path
        self.indicators = indicators
        self.status = status
    }
}

public final class ProfileScanner: ObservableObject {
    @Published public var results: [ProfileResult] = []
    @Published public var isScanning = false

    private let historyFiles = ["mcprofileevents.plist", "clienttruth.plist", "profiletruth.plist"]
    private let certificateExtensions = ["cer", "crt", "pem", "der", "p12", "pfx"]
    private let dangerousTerms = [
        "filza", "filzajailed", "filzaslop", "filzaescaped", "filzahelper", "gbox",
        "3105", "h5gg", "sileo", "roothide", "trollstore", "patcher", "stack+",
        "stackpanel", "newterm", "frida", "cycript", "debugserver", "ellekit",
        "substrate", "substitute", "dopamine", "jailbreak", "esign", "sideload"
    ]

    public init() {}

    public func scan(directoryPath: String, completion: (() -> Void)? = nil) {
        DispatchQueue.main.async {
            self.results.removeAll()
            self.isScanning = true
        }

        let root = URL(fileURLWithPath: directoryPath)

        DispatchQueue.global(qos: .userInitiated).async {
            var output: [ProfileResult] = []
            let fm = FileManager.default

            var isDirectory: ObjCBool = false
            let exists = fm.fileExists(atPath: root.path, isDirectory: &isDirectory)

            if exists && !isDirectory.boolValue {
                self.analyze(root, into: &output)
            } else if let enumerator = fm.enumerator(
                at: root,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) {
                for case let url as URL in enumerator {
                    self.analyze(url, into: &output)
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

    private func analyze(_ url: URL, into output: inout [ProfileResult]) {
        let name = url.lastPathComponent.lowercased()
        let ext = url.pathExtension.lowercased()
        let isHistory = historyFiles.contains(name)
        let isCertificate = certificateExtensions.contains(ext)
        guard isHistory || isCertificate else { return }

        let data = try? Data(contentsOf: url)
        let text = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        let lower = text.lowercased()
        let matches = Array(Set(dangerousTerms.filter { lower.contains($0) })).sorted()

        output.append(
            ProfileResult(
                fileName: url.lastPathComponent,
                path: url.path,
                indicators: matches,
                status: matches.isEmpty ? .clean : .suspicious
            )
        )
    }
}
