import { ImageResponse } from "next/og";

export const size = { width: 180, height: 180 };
export const contentType = "image/png";

export default function AppleIcon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#0a0e1a",
          borderRadius: 36,
          border: "4px solid #6366f1",
        }}
      >
        <div style={{ color: "#818cf8", fontSize: 96, fontWeight: 800, fontFamily: "system-ui" }}>A</div>
      </div>
    ),
    { ...size },
  );
}
