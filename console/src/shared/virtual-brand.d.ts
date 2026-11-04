declare module "virtual:brand" {
  export const COLORS: Readonly<Record<"ink" | "bone" | "verify" | "alert" | "muted", string>>;
  export const MOTION_MS: Readonly<Record<"seam-snap" | "mismatch-open" | "mismatch-shake" | "alert-enter" | "bubble-enter", number>>;
}
declare module "virtual:brand.css";
