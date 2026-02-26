/**
 * Bitwarden-compatible cryptographic operations.
 *
 * Key hierarchy:
 *   masterPassword + email → masterKey (PBKDF2/Argon2id)
 *   masterKey → stretchedMasterKey (HKDF-Expand: encKey || macKey)
 *   masterKey + masterPassword → masterPasswordHash (PBKDF2, 1 iter, sent to server)
 *   stretchedMasterKey → decrypt(protectedSymmetricKey) → userEncKey || userMacKey
 *   userEncKey + userMacKey → decrypt all vault data (EncStrings)
 */
import { EncType, KdfType } from './types';

const ENC = new TextEncoder();

/** Derive the 256-bit master key from the user's password and email.
 *  PBKDF2 uses email directly as salt.
 *  Argon2id uses SHA-256(email) as salt. */
export const deriveMasterKey = async (
    password: string,
    email: string,
    kdf: KdfType,
    iterations: number,
    memory?: number | null,
    parallelism?: number | null
): Promise<ArrayBuffer> => {
    const emailLower = email.toLowerCase();

    if (kdf === KdfType.PBKDF2) {
        const passwordKey = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, [
            'deriveBits',
        ]);

        return crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt: ENC.encode(emailLower), iterations, hash: 'SHA-256' },
            passwordKey,
            256
        );
    }

    if (kdf === KdfType.Argon2id) {
        // Argon2id uses SHA-256 of the email as salt
        const emailHash = await crypto.subtle.digest('SHA-256', ENC.encode(emailLower));

        // Use the argon2id WASM module (already a dependency of the extension)
        const { hash } = await import('argon2id');
        const result = await hash({
            password: ENC.encode(password),
            salt: new Uint8Array(emailHash),
            t: iterations,
            m: (memory ?? 64) * 1024, // memory is in MiB from API, argon2 wants KiB
            p: parallelism ?? 4,
            hashLength: 32,
        });

        return result.buffer;
    }

    throw new Error(`Unsupported KDF type: ${kdf}`);
};

/** Stretch the 256-bit master key into a 512-bit stretched key (encKey || macKey)
 *  using HKDF-Expand with info strings "enc" and "mac". */
export const stretchMasterKey = async (masterKey: ArrayBuffer): Promise<{ encKey: ArrayBuffer; macKey: ArrayBuffer }> => {
    const hkdfKey = await crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveBits']);

    const encKey = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: ENC.encode('enc') },
        hkdfKey,
        256
    );

    const macKey = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: ENC.encode('mac') },
        hkdfKey,
        256
    );

    return { encKey, macKey };
};

/** Compute the master password hash sent to the server for authentication.
 *  This is PBKDF2-SHA256(masterKey, masterPassword, 1 iteration), base64-encoded. */
export const hashMasterPassword = async (masterKey: ArrayBuffer, password: string): Promise<string> => {
    const key = await crypto.subtle.importKey('raw', masterKey, 'PBKDF2', false, ['deriveBits']);

    const hash = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: ENC.encode(password), iterations: 1, hash: 'SHA-256' },
        key,
        256
    );

    return uint8ToBase64(new Uint8Array(hash));
};

/** Parse a Bitwarden EncString (CipherString) into its components.
 *  Format: "<encType>.<iv>|<ciphertext>|<mac>" */
export const parseEncString = (
    encString: string
): { encType: EncType; iv: Uint8Array; ciphertext: Uint8Array; mac: Uint8Array | null } => {
    const dotIndex = encString.indexOf('.');
    const encType = parseInt(encString.substring(0, dotIndex), 10) as EncType;
    const parts = encString.substring(dotIndex + 1).split('|');

    const iv = base64ToUint8(parts[0]);
    const ciphertext = base64ToUint8(parts[1]);
    const mac = parts.length > 2 ? base64ToUint8(parts[2]) : null;

    return { encType, iv, ciphertext, mac };
};

/** Decrypt a Bitwarden EncString using the provided encryption and MAC keys. */
export const decryptEncString = async (
    encString: string,
    encKey: ArrayBuffer,
    macKey: ArrayBuffer
): Promise<ArrayBuffer> => {
    const { encType, iv, ciphertext, mac } = parseEncString(encString);

    // Verify HMAC if present (encType 2)
    if (encType === EncType.AesCbc256HmacSha256) {
        if (!mac) throw new Error('EncString type 2 requires MAC');

        const hmacKey = await crypto.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, [
            'verify',
        ]);

        // HMAC is computed over iv + ciphertext
        const data = new Uint8Array(iv.length + ciphertext.length);
        data.set(iv);
        data.set(ciphertext, iv.length);

        const valid = await crypto.subtle.verify('HMAC', hmacKey, mac, data);
        if (!valid) throw new Error('HMAC verification failed');
    }

    // Decrypt with AES-256-CBC
    const aesKey = await crypto.subtle.importKey('raw', encKey, { name: 'AES-CBC' }, false, ['decrypt']);

    return crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, ciphertext);
};

/** Decrypt the Protected Symmetric Key from the login response.
 *  Returns the 64-byte user symmetric key (first 32 = encKey, last 32 = macKey). */
export const decryptProtectedSymmetricKey = async (
    protectedKey: string,
    stretchedEncKey: ArrayBuffer,
    stretchedMacKey: ArrayBuffer
): Promise<{ userEncKey: ArrayBuffer; userMacKey: ArrayBuffer }> => {
    const decrypted = await decryptEncString(protectedKey, stretchedEncKey, stretchedMacKey);
    const bytes = new Uint8Array(decrypted);

    if (bytes.length !== 64) throw new Error(`Expected 64-byte symmetric key, got ${bytes.length}`);

    return {
        userEncKey: bytes.slice(0, 32).buffer,
        userMacKey: bytes.slice(32, 64).buffer,
    };
};

/** Create an EncString by encrypting data with AES-256-CBC + HMAC-SHA256. */
export const encryptToEncString = async (
    data: ArrayBuffer,
    encKey: ArrayBuffer,
    macKey: ArrayBuffer
): Promise<string> => {
    const iv = crypto.getRandomValues(new Uint8Array(16));

    const aesKey = await crypto.subtle.importKey('raw', encKey, { name: 'AES-CBC' }, false, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, data));

    // Compute HMAC over iv + ciphertext
    const hmacKey = await crypto.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const hmacData = new Uint8Array(iv.length + ciphertext.length);
    hmacData.set(iv);
    hmacData.set(ciphertext, iv.length);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, hmacData));

    return `2.${uint8ToBase64(iv)}|${uint8ToBase64(ciphertext)}|${uint8ToBase64(mac)}`;
};

// --- Base64 helpers ---

const uint8ToBase64 = (bytes: Uint8Array): string => {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
};

const base64ToUint8 = (b64: string): Uint8Array => {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
};
