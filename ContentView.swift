import SwiftUI
import UniformTypeIdentifiers

public struct ContentView: View {
    @StateObject private var fileManager = FileAccessManager.shared
    @StateObject private var crashScanner = CrashReportScanner()
    @StateObject private var batteryScanner = BatteryScanner()
    @StateObject private var profileScanner = ProfileScanner()
    @StateObject private var privacyAnalyzer = AppPrivacyAnalyzer()

    @State private var activeSection = "RESULTS"
    @State private var showImporter = false
    @State private var importMode = "SCAN"
    @State private var statusMessage = "جاهز للفحص"

    public init() {}

    public var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            VStack(spacing: 9) {
                header
                statusLegend

                HStack {
                    Circle().fill(Color.red).frame(width: 7, height: 7)
                    Text(statusMessage)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.gray)
                    Spacer()
                }
                .padding(.horizontal, 4)

                VStack(spacing: 7) {
                    actionButton("🔍 SCAN", mode: "SCAN", message: "اختر مجلد أو ملفات للفحص")
                    actionButton("💥 Crash Scan", mode: "CRASH", message: "اختر مجلد CrashReporter")
                    actionButton("🔋 Battery Scan", mode: "BATTERY", message: "اختر BatteryLife / Powerlog")
                    actionButton("⚙️ Profile Scan", mode: "PROFILE", message: "اختر ConfigurationProfiles")
                    actionButton("🛡️ Privacy Report", mode: "PRIVACY", message: "اختر App Privacy Report")
                }

                Divider().background(Color.gray.opacity(0.3))

                VStack(alignment: .leading, spacing: 6) {
                    Text("RESULTS [ \(activeSection) ]")
                        .font(.system(size: 12, weight: .black))
                        .foregroundColor(.red)

                    ScrollView {
                        VStack(spacing: 7) {
                            resultsView
                        }
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color.white.opacity(0.04))
                .cornerRadius(9)
            }
            .padding()
        }
        .fileImporter(
            isPresented: $showImporter,
            allowedContentTypes: [.folder, .item, .data, .json, .text],
            allowsMultipleSelection: false,
            onCompletion: handleImport
        )
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text("VOLCANO").font(.system(size: 23, weight: .black)).foregroundColor(.white)
                    Text("SENSI").font(.system(size: 23, weight: .black)).foregroundColor(.red)
                }
                Text("Security Checker").font(.system(size: 11, weight: .medium)).foregroundColor(.gray)
            }
            Spacer()
            Text("volcano16x").font(.system(size: 13, weight: .bold)).foregroundColor(.gray)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .background(Color.white.opacity(0.07))
        .cornerRadius(10)
    }

    private var statusLegend: some View {
        HStack(spacing: 12) {
            Text("🟢 Clean")
            Text("🟡 Warning")
            Text("🔴 Suspicious")
        }
        .font(.system(size: 11, weight: .bold))
        .foregroundColor(.white)
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .background(Color.white.opacity(0.06))
        .cornerRadius(8)
    }

    private func actionButton(_ title: String, mode: String, message: String) -> some View {
        ScanActionButton(title: title) {
            activeSection = mode
            importMode = mode
            statusMessage = message
            showImporter = true
        }
    }

    @ViewBuilder
    private var resultsView: some View {
        switch activeSection {
        case "SCAN":
            if fileManager.scannedFiles.isEmpty {
                EmptyResultView(icon: "🔍", text: "لم يتم العثور على نتائج")
            } else {
                ForEach(fileManager.scannedFiles) { item in
                    ResultRowCard(title: item.name, subtitle: item.path, badge: item.status.icon, reason: item.reason)
                }
            }

        case "CRASH":
            if crashScanner.results.isEmpty {
                EmptyResultView(icon: "💥", text: "لم يتم العثور على تقارير")
            } else {
                ForEach(crashScanner.results) { item in
                    ResultRowCard(
                        title: item.fileName,
                        subtitle: item.path,
                        badge: item.status.icon,
                        reason: item.matchedIndicators.isEmpty ? "لا توجد مؤشرات" : item.matchedIndicators.joined(separator: ", ")
                    )
                }
            }

        case "BATTERY":
            if batteryScanner.detectedApps.isEmpty {
                EmptyResultView(icon: "🔋", text: "لم يتم العثور على بيانات Battery")
            } else {
                ForEach(batteryScanner.detectedApps) { item in
                    ResultRowCard(title: item.appName, subtitle: item.bundleID.isEmpty ? item.eventDescription : item.bundleID, badge: item.status.icon, reason: item.eventDescription)
                }
            }

        case "PROFILE":
            if profileScanner.results.isEmpty {
                EmptyResultView(icon: "⚙️", text: "لم يتم العثور على بيانات Profile")
            } else {
                ForEach(profileScanner.results) { item in
                    ResultRowCard(
                        title: item.fileName,
                        subtitle: item.path,
                        badge: item.status.icon,
                        reason: item.indicators.isEmpty ? "لا توجد مؤشرات" : item.indicators.joined(separator: ", ")
                    )
                }
            }

        case "PRIVACY":
            if privacyAnalyzer.groupedItems.isEmpty {
                EmptyResultView(icon: "🛡️", text: "لم يتم العثور على Privacy data")
            } else {
                ForEach(privacyAnalyzer.groupedItems) { item in
                    ResultRowCard(
                        title: item.appName,
                        subtitle: item.bundleID,
                        badge: item.status.icon,
                        reason: item.reason
                    )
                }
            }

        default:
            EmptyResultView(icon: "🛡️", text: "اختر نوع الفحص")
        }
    }

    private func handleImport(_ result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            guard let url = urls.first else {
                statusMessage = "لم يتم اختيار ملف"
                return
            }

            let access = url.startAccessingSecurityScopedResource()
            statusMessage = "جاري الفحص..."

            switch importMode {
            case "SCAN":
                fileManager.runGeneralScan(targetDirectory: url.path) {
                    if access { url.stopAccessingSecurityScopedResource() }
                    statusMessage = "اكتمل الفحص العام"
                }

            case "CRASH":
                crashScanner.scanCrashReports(directoryPath: url.path) {
                    if access { url.stopAccessingSecurityScopedResource() }
                    statusMessage = "اكتمل فحص Crash Reports"
                }

            case "BATTERY":
                batteryScanner.scanBatteryAndProfileData(baseDirectory: url.path) {
                    if access { url.stopAccessingSecurityScopedResource() }
                    statusMessage = "اكتمل فحص Battery / Powerlog"
                }

            case "PROFILE":
                profileScanner.scan(directoryPath: url.path) {
                    if access { url.stopAccessingSecurityScopedResource() }
                    statusMessage = "اكتمل فحص ConfigurationProfiles"
                }

            case "PRIVACY":
                defer {
                    if access { url.stopAccessingSecurityScopedResource() }
                }

                do {
                    let data = try Data(contentsOf: url)
                    var entries = AppPrivacyReportParser.parseNDJSON(from: data)
                    if entries.isEmpty {
                        entries = AppPrivacyReportParser.parseJSON(from: data)
                    }
                    privacyAnalyzer.analyzeAndGroup(rawEntries: entries)
                    statusMessage = "تم تحميل \(entries.count) سجل Privacy"
                } catch {
                    statusMessage = "فشل قراءة Privacy Report"
                }

            default:
                if access { url.stopAccessingSecurityScopedResource() }
            }

        case .failure(let error):
            statusMessage = "فشل اختيار الملف: \(error.localizedDescription)"
        }
    }
}

public struct ScanActionButton: View {
    public let title: String
    public let action: () -> Void

    public init(title: String, action: @escaping () -> Void) {
        self.title = title
        self.action = action
    }

    public var body: some View {
        Button(action: action) {
            HStack {
                Text(title).font(.system(size: 14, weight: .bold)).foregroundColor(.white)
                Spacer()
                Image(systemName: "chevron.right").font(.system(size: 11, weight: .bold)).foregroundColor(.gray)
            }
            .padding(.horizontal, 13)
            .padding(.vertical, 10)
            .frame(maxWidth: .infinity)
            .background(Color.white.opacity(0.08))
            .cornerRadius(8)
        }
        .buttonStyle(.plain)
    }
}

public struct ResultRowCard: View {
    public let title: String
    public let subtitle: String
    public let badge: String
    public let reason: String

    public init(title: String, subtitle: String, badge: String, reason: String) {
        self.title = title
        self.subtitle = subtitle
        self.badge = badge
        self.reason = reason
    }

    public var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 13, weight: .bold)).foregroundColor(.white).lineLimit(1)
                Text(subtitle).font(.system(size: 9)).foregroundColor(.gray).lineLimit(1)
                Text(reason).font(.system(size: 10, weight: .semibold)).foregroundColor(.gray).lineLimit(2)
            }
            Spacer()
            Text(badge).font(.system(size: 17))
        }
        .padding(10)
        .frame(maxWidth: .infinity)
        .background(Color.white.opacity(0.055))
        .cornerRadius(7)
    }
}

public struct EmptyResultView: View {
    public let icon: String
    public let text: String

    public init(icon: String, text: String) {
        self.icon = icon
        self.text = text
    }

    public var body: some View {
        VStack(spacing: 8) {
            Text(icon).font(.system(size: 28))
            Text(text).font(.system(size: 12, weight: .medium)).foregroundColor(.gray)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 35)
    }
}
