declare module "virtual:brand" {
  export const COLORS: Readonly<Record<"ink" | "bone" | "verify" | "alert" | "muted", string>>;
  export const MOTION_MS: Readonly<Record<string, number>>;
}
declare module "virtual:brand.css";
