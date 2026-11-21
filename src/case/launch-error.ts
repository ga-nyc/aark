/** No engine was submitted for this token, so its reserved slot can be released. */
export class EngineLaunchRefusedError extends Error {
  public constructor() {
    super("case engine refused before launch");
    this.name = "EngineLaunchRefusedError";
  }
}

/** The host proved cancellation before any submission for this token; its intent stays pending. */
export class EngineLaunchCancelledError extends Error {
  public constructor() {
    super("case engine cancelled before submission");
    this.name = "EngineLaunchCancelledError";
  }
}

/** Metadata/capacity is not ready; this same reviewed intent must wait, not fail. */
export class EngineLaunchDeferredError extends Error {
  public constructor(readonly unsubmitted: boolean, readonly reason: "capacity-wait" | "observation-unavailable") {
    super("case engine launch awaits a fresh metadata observation");
    this.name = "EngineLaunchDeferredError";
  }
}
