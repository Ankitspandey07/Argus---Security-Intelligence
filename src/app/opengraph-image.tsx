import { ImageResponse } from "next/og";

export const alt = "Argus — Web & API Security Intelligence";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpenGraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          alignItems: "flex-start",
          justifyContent: "center",
          padding: 72,
          background: "linear-gradient(145deg, #0a0e1a 0%, #111827 45%, #1e1b4b 100%)",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 20,
            marginBottom: 28,
          }}
        >
          <div
            style={{
              width: 72,
              height: 72,
              borderRadius: 16,
              background: "rgba(99, 102, 241, 0.2)",
              border: "2px solid #6366f1",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "#a5b4fc",
              fontSize: 36,
              fontWeight: 800,
            }}
          >
            A
          </div>
          <div style={{ display: "flex", flexDirection: "column" }}>
            <span style={{ fontSize: 56, fontWeight: 800, color: "#f9fafb", letterSpacing: -1 }}>Argus</span>
            <span style={{ fontSize: 22, color: "#9ca3af", marginTop: 4 }}>Security Intelligence</span>
          </div>
        </div>
        <p style={{ fontSize: 28, color: "#d1d5db", maxWidth: 900, lineHeight: 1.4, margin: 0 }}>
          Headers, TLS, ports, secrets, and AI-assisted reporting — scan what you are authorized to test.
        </p>
      </div>
    ),
    { ...size },
  );
}
