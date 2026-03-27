import type { Locale, Messages } from "./types";

export async function getMessages(locale: Locale): Promise<Messages> {
  switch (locale) {
    case "es":
      return (await import("./messages/es.json")).default as Messages;
    case "fr":
      return (await import("./messages/fr.json")).default as Messages;
    case "de":
      return (await import("./messages/de.json")).default as Messages;
    case "pt":
      return (await import("./messages/pt.json")).default as Messages;
    case "ja":
      return (await import("./messages/ja.json")).default as Messages;
    case "hi":
      return (await import("./messages/hi.json")).default as Messages;
    case "zh":
      return (await import("./messages/zh.json")).default as Messages;
    case "en":
    default:
      return (await import("./messages/en.json")).default as Messages;
  }
}
