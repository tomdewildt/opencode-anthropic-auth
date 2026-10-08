export type RateLimitCategory = 'fast-mode-credits' | 'subscription-usage' | 'transient-rate-limit' | 'unknown-rate-limit';
export type RateLimitEnhancement = {
    readonly response: Response;
    readonly category: RateLimitCategory;
};
type ConnectionInfo = {
    readonly type: string;
    readonly id?: string;
    readonly label?: string;
};
type RateLimitOptions = {
    readonly probeTimeoutMs?: number;
};
export declare function createConnectionLabel(entropy?: Uint8Array): string;
export declare function describeConnection(connection: ConnectionInfo): string;
export declare function isSubscriptionUsageDiagnostic(message: string): boolean;
export declare function enhanceRateLimitResponse(response: Response, connection: string, options?: RateLimitOptions): Promise<RateLimitEnhancement>;
export {};
