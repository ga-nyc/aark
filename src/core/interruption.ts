/** Raised at an explicit cancellation check. Concurrent I/O errors stay independent. */
export class OperationInterruptedError extends Error {}
