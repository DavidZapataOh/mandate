import "@fontsource/inter/latin-400.css";
import "@fontsource/inter/latin-700.css";
import "@fontsource/inter/latin-800.css";
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-700.css";
import "./explorer/explorer.css";
import { mountExplorer } from "./explorer/view";

mountExplorer(document, (url, init) => fetch(url, init));
