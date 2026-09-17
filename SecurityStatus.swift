import Foundation

public enum SecurityStatus: String, Codable, CaseIterable {
    case clean
    case warning
    case suspicious

    public var title: String {
        switch self {
        case .clean: return "Clean"
        case .warning: return "Warning"
        case .suspicious: return "Suspicious"
        }
    }

    public var icon: String {
        switch self {
        case .clean: return "🟢"
        case .warning: return "🟡"
        case .suspicious: return "🔴"
        }
    }

    public var priority: Int {
        switch self {
        case .suspicious: return 3
        case .warning: return 2
        case .clean: return 1
        }
    }
}
