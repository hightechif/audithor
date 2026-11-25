import SwiftUI

extension Severity {
    var color: Color {
        switch self {
        case .critical: return Color(red: 0.62, green: 0.08, blue: 0.12)
        case .high: return Color(red: 0.86, green: 0.27, blue: 0.18)
        case .medium: return Color(red: 0.90, green: 0.58, blue: 0.0)
        case .low: return Color(red: 0.23, green: 0.48, blue: 0.84)
        case .info: return .gray
        }
    }

    var symbol: String {
        switch self {
        case .critical: return "exclamationmark.octagon.fill"
        case .high: return "exclamationmark.triangle.fill"
        case .medium: return "exclamationmark.circle.fill"
        case .low: return "info.circle.fill"
        case .info: return "circle.fill"
        }
    }
}

struct SeverityPill: View {
    let severity: Severity

    var body: some View {
        Text(severity.title.uppercased())
            .font(.system(size: 10, weight: .bold))
            .foregroundStyle(.white)
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(Capsule().fill(severity.color))
            .accessibilityLabel("\(severity.title) severity")
    }
}

struct RiskBadge: View {
    let score: Int
    var compact = false

    var color: Color {
        switch score {
        case 0..<15: return .green
        case 15..<40: return .yellow
        case 40..<70: return .orange
        default: return .red
        }
    }

    var body: some View {
        Text("\(score)")
            .font(.system(size: compact ? 11 : 14, weight: .bold, design: .rounded))
            .monospacedDigit()
            .frame(width: compact ? 28 : 40, height: compact ? 20 : 26)
            .background(RoundedRectangle(cornerRadius: 5).fill(color.opacity(0.25)))
            .overlay(RoundedRectangle(cornerRadius: 5).stroke(color, lineWidth: 1))
            .accessibilityLabel("Risk score \(score)")
    }
}

struct RiskGauge: View {
    let score: Int

    var body: some View {
        ZStack {
            Circle().stroke(Color.secondary.opacity(0.2), lineWidth: 12)
            Circle()
                .trim(from: 0, to: CGFloat(score) / 100)
                .stroke(AngularGradient(colors: [.green, .yellow, .orange, .red], center: .center,
                                        startAngle: .degrees(0), endAngle: .degrees(360 * Double(max(score, 1)) / 100)),
                        style: StrokeStyle(lineWidth: 12, lineCap: .round))
                .rotationEffect(.degrees(-90))
            VStack(spacing: 0) {
                Text("\(score)").font(.system(size: 34, weight: .bold, design: .rounded)).monospacedDigit()
                Text(ScanResult.riskLabel(for: score)).font(.caption).foregroundStyle(.secondary)
            }
        }
        .frame(width: 120, height: 120)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Overall risk \(score) of 100, \(ScanResult.riskLabel(for: score))")
    }
}

struct CopyButton: View {
    let text: String
    var label = "Copy"
    @State private var copied = false

    var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
            copied = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { copied = false }
        } label: {
            Label(copied ? "Copied" : label, systemImage: copied ? "checkmark" : "doc.on.doc")
        }
        .help("Copy to clipboard")
    }
}

/// Simple flow layout for chips (macOS 13 `Layout`).
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0, maxX: CGFloat = 0
        for v in subviews {
            let s = v.sizeThatFits(.unspecified)
            if x + s.width > width, x > 0 { x = 0; y += rowHeight + spacing; rowHeight = 0 }
            x += s.width + spacing
            maxX = max(maxX, x)
            rowHeight = max(rowHeight, s.height)
        }
        return CGSize(width: min(maxX, width), height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowHeight: CGFloat = 0
        for v in subviews {
            let s = v.sizeThatFits(.unspecified)
            if x + s.width > bounds.maxX, x > bounds.minX { x = bounds.minX; y += rowHeight + spacing; rowHeight = 0 }
            v.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(s))
            x += s.width + spacing
            rowHeight = max(rowHeight, s.height)
        }
    }
}
