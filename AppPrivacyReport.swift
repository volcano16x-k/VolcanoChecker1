import Foundation

public struct PrivacyRawEntry: Codable {
    public let accessor: AccessorInfo?
    public let category: String?
    public let identifier: String?
    public let timeStamp: String?
    public let type: String?

    public struct AccessorInfo: Codable {
        public let identifier: String?
        public let identifierType: String?

        public init(identifier: String?, identifierType: String?) {
            self.identifier = identifier
            self.identifierType = identifierType
        }
    }

    public init(accessor: AccessorInfo?, category: String?, identifier: String?, timeStamp: String?, type: String?) {
        self.accessor = accessor
        self.category = category
        self.identifier = identifier
        self.timeStamp = timeStamp
        self.type = type
    }
}

public final class AppPrivacyReportParser {
    public static func parseNDJSON(from data: Data) -> [PrivacyRawEntry] {
        guard let text = String(data: data, encoding: .utf8) else { return [] }
        let decoder = JSONDecoder()
        var results: [PrivacyRawEntry] = []

        for line in text.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, let lineData = trimmed.data(using: .utf8) else { continue }
            if let entry = try? decoder.decode(PrivacyRawEntry.self, from: lineData) {
                results.append(entry)
            }
        }
        return results
    }

    public static func parseJSON(from data: Data) -> [PrivacyRawEntry] {
        let decoder = JSONDecoder()
        if let array = try? decoder.decode([PrivacyRawEntry].self, from: data) { return array }
        if let single = try? decoder.decode(PrivacyRawEntry.self, from: data) { return [single] }
        return []
    }
}
