function base64UrlEncode(bytes) {
    let bin = '';
    for (const byte of bytes)
        bin += String.fromCharCode(byte);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
export async function generatePKCE() {
    const buf = new Uint8Array(64);
    crypto.getRandomValues(buf);
    const verifier = base64UrlEncode(buf);
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    return {
        verifier,
        challenge: base64UrlEncode(new Uint8Array(digest)),
        method: 'S256',
    };
}
