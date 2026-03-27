import { ImageResponse } from "next/og";

export const size = { width: 32, height: 32 };
export const contentType = "image/png";

export default function Icon() {
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
          borderRadius: 8,
          border: "2px solid #6366f1",
        }}
      >
        <div style={{ color: "#818cf8", fontSize: 18, fontWeight: 800, fontFamily: "system-ui" }}>A</div>
      </div>
    ),
    { ...size },
  );
}
