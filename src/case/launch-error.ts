/** No engine was submitted for this token, so its reserved slot can be released. */
export class EngineLaunchRefusedError extends Error {
  public constructor() {
    super("case engine refused before launch");
    this.name = "EngineLaunchRefusedError";
  }
}
