import { withInheritedCommandGroup } from "../core/command.js";

/** Nested metadata commands stay inside the disposable aggregate probe's group. */
export async function runCaseProbe(action: () => Promise<void>): Promise<void> {
  await withInheritedCommandGroup(action);
}
