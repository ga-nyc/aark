import type { Candidate } from "../core/types.js";
import type { DetectionContext } from "./detectors/types.js";

export type DetectorJobKind =
  | "cryptographic-keys"
  | "configuration-secrets"
  | "wallet-secrets"
  | "provider-credentials"
  | "streaming"
  | "small-file"
  | "cryptocurrency-streaming"
  | "cryptocurrency-small-file"
  | "cryptocurrency-structured"
  | "deep-key-schedules"
  | "structured";

export const STREAMING_DETECTOR_NAMES = [
  "cryptographic-keys",
  "configuration-secrets",
  "wallet-secrets",
  "provider-credentials",
] as const;

export const CRYPTOCURRENCY_STREAMING_DETECTOR_NAMES = ["wallet-secrets"] as const;

export function expectedDetectorNames(kind: DetectorJobKind): readonly string[] {
  switch (kind) {
    case "streaming":
      return STREAMING_DETECTOR_NAMES;
    case "small-file":
      return [...STREAMING_DETECTOR_NAMES, "structured-artifacts"];
    case "cryptocurrency-streaming":
      return CRYPTOCURRENCY_STREAMING_DETECTOR_NAMES;
    case "cryptocurrency-small-file":
      return [...CRYPTOCURRENCY_STREAMING_DETECTOR_NAMES, "structured-artifacts"];
    case "cryptocurrency-structured":
      return ["structured-artifacts"];
    case "structured":
      return ["structured-artifacts"];
    default:
      return [kind];
  }
}

export interface DetectorJobRequest {
  id: number;
  kind: DetectorJobKind;
  data: Uint8Array;
  context: DetectionContext;
}

export interface DetectorBatchResult {
  detector: string;
  candidates: Candidate[];
  error?: string;
}

export interface DetectorJobResponse {
  id: number;
  results: DetectorBatchResult[];
  fatalError?: string;
}
