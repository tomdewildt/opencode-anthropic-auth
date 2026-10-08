import { MAX_JSON_TOOL_NAME_BYTES } from './json-response-stream.ts';
export declare const MAX_SSE_LINE_BYTES: number;
export declare const MAX_SSE_EVENT_BYTES: number;
export { MAX_JSON_TOOL_NAME_BYTES };
type ToolNameAliasOptions = {
    maxEntries?: number;
    maxBytes?: number;
};
/**
 * Reversible tool-name aliases bounded to Anthropic's 64-byte limit.
 *
 * Names up to 44 UTF-8 bytes are encoded inline. Longer names use a stable
 * SHA-256 alias and are retained in a bounded table because a lossless,
 * stateless 64-byte source -> 60-byte payload mapping is impossible.
 */
export declare class ToolNameAliasTable {
    private readonly maxEntries;
    private readonly maxBytes;
    private readonly longByName;
    private readonly longByAlias;
    private retainedBytes;
    private disposed;
    constructor(options?: ToolNameAliasOptions);
    private assertActive;
    encode(name: string): string;
    decode(alias: string): string | undefined;
    get hasStatefulAliases(): boolean;
    dispose(): void;
}
export declare function headersAfterBodyTransform(source: Headers): Headers;
export type FetchInput = string | URL | Request;
/**
 * Merge headers from a Request object and/or a RequestInit headers value
 * into a single Headers instance.
 */
export declare function mergeHeaders(input: FetchInput, init?: RequestInit): Headers;
/**
 * Merge incoming beta headers with the required OAuth betas, deduplicating.
 */
export declare function mergeBetaHeaders(headers: Headers): string;
/**
 * Set OAuth-required headers on the request: authorization, beta, user-agent.
 * Removes x-api-key since we're using OAuth.
 */
export declare function setOAuthHeaders(headers: Headers, accessToken: string, version?: string): Headers;
/**
 * Add TOOL_PREFIX to tool names in the request body.
 * Prefixes both tool definitions and tool_use blocks in messages.
 */
export declare function prefixToolNames(parsed: Record<string, unknown>, alreadyPrefixed?: boolean, aliases?: ToolNameAliasTable): string;
/**
 * Strip TOOL_PREFIX from tool names in streaming response text.
 */
export declare function stripToolPrefix(text: string, aliases?: ToolNameAliasTable): string;
/** Check whether TLS verification was explicitly requested off for a custom endpoint. */
export declare function isInsecure(): boolean;
/**
 * Allow OAuth bearer credentials only for Anthropic's official API or the
 * exact origin of an explicitly configured, validated custom endpoint.
 */
export declare function isTrustedAnthropicUrl(input: string | URL): boolean;
/**
 * Rewrite the request URL to add ?beta=true for /v1/messages requests. When
 * ANTHROPIC_BASE_URL is set, override the origin for API requests while
 * retaining the original path and query.
 */
export declare function rewriteUrl(input: FetchInput): {
    input: FetchInput;
    url: URL | null;
};
/**
 * Sanitize OpenCode-branded strings from the system prompt text.
 *
 * 1. Removes the OPENCODE_IDENTITY paragraph.
 * 2. Removes any paragraph (text between blank lines) that contains
 *    one of the PARAGRAPH_REMOVAL_ANCHORS — typically URLs that
 *    identify OpenCode-specific content.
 * 3. Applies TEXT_REPLACEMENTS for inline occurrences of "OpenCode"
 *    inside paragraphs we want to keep.
 *
 * This approach is resilient to upstream rewording of the OpenCode
 * prompt — as long as the anchor strings (URLs, etc.) still appear
 * somewhere in the paragraph, the removal works.
 */
export declare function sanitizeSystemText(text: string): string;
type SystemBlock = {
    type: string;
    text: string;
    [k: string]: unknown;
};
/**
 * Sanitize system prompt and prepend Claude Code identity.
 * Handles all Anthropic API system formats: undefined, string, or array of text blocks.
 */
export declare function prependClaudeCodeIdentity(system: unknown): SystemBlock[];
/**
 * Rewrite the full request body: sanitize system prompt and prefix tool names.
 */
export declare function rewriteRequestBody(body: string, version?: string, aliases?: ToolNameAliasTable): string;
/**
 * Create a streaming response that strips the tool prefix from tool names.
 */
export declare function createStrippedStream(response: Response, aliases?: ToolNameAliasTable, onFinalize?: () => void): Response;
