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
