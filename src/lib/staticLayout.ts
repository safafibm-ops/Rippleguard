import { edges, nodes } from "../data/ecosystem";
import { computeLayeredLayout } from "./layout";

export const layoutPositions = computeLayeredLayout(nodes, edges);
