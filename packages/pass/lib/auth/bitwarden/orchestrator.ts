/**
 * Bitwarden auth orchestrator.
 *
 * Coordinates the full login flow:
 *   1. Pre-login → get KDF params
 *   2. Derive master key (PBKDF2 or Argon2id)
 *   3. Stretch master key → encKey + macKey
 *   4. Hash master password → send to server
 *   5. Login → get tokens + encrypted symmetric key
 *   6. Decrypt protected symmetric key → user encKey + macKey
 *   7. Store session
 */
import {
    decryptProtectedSymmetricKey,
    deriveMasterKey,
    hashMasterPassword,
    stretchMasterKey,
} from './crypto';
import { type BitwardenApi, type BitwardenApiConfig, createBitwardenApi } from './api';
import type { BitwardenSession, KdfType } from './types';

export type LoginResult = {
    session: BitwardenSession;
    userEncKey: ArrayBuffer;
    userMacKey: ArrayBuffer;
};

export type AuthOrchestratorConfig = BitwardenApiConfig & {
    /** Device identifier (UUID, persisted per installation) */
    deviceIdentifier: string;
    /** Human-readable device name */
    deviceName: string;
    /** Numeric device type enum (7 = Chrome, 3 = Firefox) */
    deviceType: number;
};

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

export const createAuthOrchestrator = (config: AuthOrchestratorConfig) => {
    const api: BitwardenApi = createBitwardenApi(config);

    return {
        api,

        /** Full login flow: email + password → authenticated session with decrypted keys. */
        login: async (
            email: string,
            password: string,
            twoFactor?: { token: string; provider: number; remember?: boolean }
        ): Promise<LoginResult> => {
            // Step 1: Pre-login to get KDF parameters
            const preLogin = await api.preLogin(email);

            // Step 2: Derive master key
            const masterKey = await deriveMasterKey(
                password,
                email,
                preLogin.Kdf,
                preLogin.KdfIterations,
                preLogin.KdfMemory,
                preLogin.KdfParallelism
            );

            // Step 3: Stretch master key → encKey + macKey
            const stretched = await stretchMasterKey(masterKey);

            // Step 4: Compute master password hash for server auth
            const masterPasswordHash = await hashMasterPassword(masterKey, password);

            // Step 5: Authenticate with server
            const loginResponse = await api.login({
                email,
                masterPasswordHash,
                deviceIdentifier: config.deviceIdentifier,
                deviceName: config.deviceName,
                deviceType: config.deviceType,
                twoFactorToken: twoFactor?.token,
                twoFactorProvider: twoFactor?.provider,
                twoFactorRemember: twoFactor?.remember,
            });

            // Step 6: Set the access token for subsequent API calls
            api.setAccessToken(loginResponse.access_token);

            // Step 7: Decrypt the protected symmetric key
            const { userEncKey, userMacKey } = await decryptProtectedSymmetricKey(
                loginResponse.Key,
                stretched.encKey,
                stretched.macKey
            );

            // Step 8: Build the session object
            const session: BitwardenSession = {
                accessToken: loginResponse.access_token,
                refreshToken: loginResponse.refresh_token,
                expiresAt: Date.now() + loginResponse.expires_in * 1000,
                kdf: loginResponse.Kdf,
                kdfIterations: loginResponse.KdfIterations,
                kdfMemory: loginResponse.KdfMemory,
                kdfParallelism: loginResponse.KdfParallelism,
                userSymmetricKey: uint8ToBase64(
                    new Uint8Array([...new Uint8Array(userEncKey), ...new Uint8Array(userMacKey)])
                ),
                encryptedPrivateKey: loginResponse.PrivateKey,
                userEmail: email,
                userId: '', // Will be populated from sync
            };

            return { session, userEncKey, userMacKey };
        },

        /** Refresh the access token using the stored refresh token. */
        refresh: async (refreshToken: string): Promise<{ accessToken: string; refreshToken: string; expiresAt: number }> => {
            const response = await api.refreshToken(refreshToken);
            api.setAccessToken(response.access_token);

            return {
                accessToken: response.access_token,
                refreshToken: response.refresh_token,
                expiresAt: Date.now() + response.expires_in * 1000,
            };
        },

        /** Full sync: fetch profile + all vault data. Populates session.userId. */
        sync: async (session: BitwardenSession): Promise<{ session: BitwardenSession; sync: Awaited<ReturnType<BitwardenApi['sync']>> }> => {
            api.setAccessToken(session.accessToken);
            const syncData = await api.sync();

            return {
                session: { ...session, userId: syncData.Profile.Id },
                sync: syncData,
            };
        },

        /** Decrypt a single EncString using the user's symmetric key from session. */
        decryptString: async (
            encString: string | null | undefined,
            userSymmetricKeyB64: string
        ): Promise<string | null> => {
            if (!encString) return null;

            const { decryptEncString } = await import('./crypto');
            const keyBytes = base64ToUint8(userSymmetricKeyB64);
            const encKey = keyBytes.slice(0, 32).buffer;
            const macKey = keyBytes.slice(32, 64).buffer;

            const decrypted = await decryptEncString(encString, encKey, macKey);
            return new TextDecoder().decode(decrypted);
        },
    };
};

export type AuthOrchestrator = ReturnType<typeof createAuthOrchestrator>;
