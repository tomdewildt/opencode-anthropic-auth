/**
 * Environment variable that overrides the reported Claude Code version.
 *
 * Anthropic gates model access on the reported version server-side, and that
 * gate moves on Anthropic's schedule rather than this plugin's release
 * schedule. The override lets users unblock a newly-gated model without
 * waiting for a published bump.
 */
export declare const ANTHROPIC_CLAUDE_CODE_VERSION_ENV_VAR = "ANTHROPIC_CLAUDE_CODE_VERSION";
export declare function isValidClaudeCodeVersion(candidate: string): boolean;
/**
 * Compare two validated Claude Code releases.
 *
 * Components are compared numerically rather than lexically — `2.1.99` sorts
 * after `2.1.280` as a string but is the older release — and as `BigInt`, so a
 * large bounded component cannot silently lose precision the way `Number`
 * would. Invalid input has no ordering and returns `undefined`.
 */
export declare function compareClaudeCodeVersions(candidate: string, baseline: string): -1 | 0 | 1 | undefined;
/**
 * Outcome of reading the version override.
 *
 * The invalid arm carries no version: a malformed override must never reach
 * the request path, so callers cannot accidentally report one. The outdated
 * arm does carry one — an explicit older version is still honoured — but pairs
 * it with the warning explaining why reporting it is risky.
 */
export type ClaudeCodeVersionResolution = {
    readonly type: 'success';
    readonly version: string;
} | {
    readonly type: 'outdated';
    readonly version: string;
    readonly warning: string;
} | {
    readonly type: 'invalid';
    readonly error: string;
};
/**
 * Resolve the Claude Code version to report to Anthropic.
 *
 * Returns the bundled version when the override is unset. A set override is
 * trimmed and must look like a Claude Code release; anything else resolves to
 * `invalid` with a message describing how to correct it. An override older
 * than the bundled version resolves to `outdated`: it is still reported, since
 * it was set deliberately, but it can lock the user out of newer models.
 * Never throws.
 */
export declare function resolveClaudeCodeVersion(raw?: string | undefined): ClaudeCodeVersionResolution;
