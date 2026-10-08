export declare class BodyLimitError extends Error {
    constructor(label: string, limit: number);
}
export declare class InvalidUtf8Error extends Error {
    constructor(label: string);
}
export declare function contentLength(headers: Headers): number | undefined;
export declare function readBoundedText(body: ReadableStream<Uint8Array> | null, limit: number, label: string): Promise<string>;
