type Message = {
    role?: string;
    content?: string | Array<{
        type?: string;
        text?: string;
    }>;
};
/**
 * Extract text from the first user message's first text block.
 */
export declare function extractFirstUserMessageText(messages: Message[]): string;
/**
 * Compute cch: first 5 hex characters of SHA-256(messageText).
 */
export declare function computeCCH(messageText: string): string;
/**
 * Compute the 3-char version suffix from the sampled message characters.
 */
export declare function computeVersionSuffix(messageText: string, version?: string): string;
/**
 * Build the complete billing header string for insertion into system[0].
 */
export declare function buildBillingHeaderValue(messages: Message[], version: string | undefined, entrypoint: string): string;
export {};
