export declare function generatePKCE(): Promise<{
    verifier: string;
    challenge: string;
    method: 'S256';
}>;
