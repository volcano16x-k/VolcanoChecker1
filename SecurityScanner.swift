import Foundation

public final class SecurityScanner {
    public init() {}

    public func statusFor(name: String, content: String) -> SecurityStatus {
        let combined = "\(name) \(content)".lowercased()
        let dangerous = ["filza", "trollstore", "jailbreak", "stack+", "h5gg", "gbox", "frida", "external", "vip"]
        let warning = ["proxy", "vpn", "shadowrocket", "surge", "quantumult", "clash"]

        if dangerous.contains(where: { combined.contains($0) }) { return .suspicious }
        if warning.contains(where: { combined.contains($0) }) { return .warning }
        return .clean
    }
}
