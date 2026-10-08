export interface ClaudeCodeVersionRejection {
    readonly rejectedVersion: string;
    readonly requiredVersion: string;
}
/**
 * Parse only Anthropic's structured minimum-version rejection.
 *
 * The error code is authoritative; the bounded message supplies the versions.
 * Requiring the rejected version to equal what this setup actually sent keeps
 * an unrelated or stale response from changing later requests.
 */
export declare function parseClaudeCodeVersionRejection(body: string, reportedVersion: string): ClaudeCodeVersionRejection | undefined;
/**
 * Inspect a clone so the provider still receives the original response body.
 * Any malformed, oversized, non-JSON, or non-400 response is ignored.
 */
export declare function detectClaudeCodeVersionRejection(response: Response, reportedVersion: string): Promise<ClaudeCodeVersionRejection | undefined>;
