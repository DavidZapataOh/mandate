import "./shared/brand";
import "./explorer/explorer.css";
import { mountExplorer } from "./explorer/view";

mountExplorer(document, (url, init) => fetch(url, init));
