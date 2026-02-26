/**
 * Bitwarden/Vaultwarden API client.
 *
 * Handles pre-login, authentication, token refresh, and sync operations
 * against a Vaultwarden-compatible API endpoint.
 */
import type {
    CipherResponse,
    LoginResponse,
    PreLoginResponse,
    RefreshResponse,
    SyncResponse,
    TwoFactorRequired,
} from './types';

export type BitwardenApiConfig = {
    /** Base URL of the Vaultwarden instance (e.g., "https://vault.southernwind.xyz") */
    baseUrl: string;
};

export class BitwardenApiError extends Error {
    constructor(
        message: string,
        public status: number,
        public response?: unknown
    ) {
        super(message);
        this.name = 'BitwardenApiError';
    }
}

export class TwoFactorRequiredError extends Error {
    constructor(public providers: TwoFactorRequired['TwoFactorProviders2']) {
        super('Two-factor authentication required');
        this.name = 'TwoFactorRequiredError';
    }
}

const createBitwardenApi = (config: BitwardenApiConfig) => {
    let accessToken: string | null = null;

    const headers = (extra?: Record<string, string>): HeadersInit => ({
        ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        ...extra,
    });

    const jsonPost = async <T>(path: string, body: Record<string, unknown>): Promise<T> => {
        const res = await fetch(`${config.baseUrl}${path}`, {
            method: 'POST',
            headers: headers({ 'Content-Type': 'application/json' }),
            body: JSON.stringify(body),
        });

        if (!res.ok) throw new BitwardenApiError(`${path} failed: ${res.status}`, res.status, await res.json().catch(() => null));
        return res.json();
    };

    const formPost = async <T>(path: string, body: Record<string, string>): Promise<T> => {
        const res = await fetch(`${config.baseUrl}${path}`, {
            method: 'POST',
            headers: headers({ 'Content-Type': 'application/x-www-form-urlencoded' }),
            body: new URLSearchParams(body).toString(),
        });

        if (!res.ok) {
            const data = await res.json().catch(() => null);

            // Check for 2FA required response
            if (res.status === 400 && data?.TwoFactorProviders2) {
                throw new TwoFactorRequiredError(data.TwoFactorProviders2);
            }

            throw new BitwardenApiError(`${path} failed: ${res.status}`, res.status, data);
        }

        return res.json();
    };

    const jsonGet = async <T>(path: string): Promise<T> => {
        const res = await fetch(`${config.baseUrl}${path}`, {
            method: 'GET',
            headers: headers({ Accept: 'application/json' }),
        });

        if (!res.ok) throw new BitwardenApiError(`${path} failed: ${res.status}`, res.status, await res.json().catch(() => null));
        return res.json();
    };

    return {
        setAccessToken: (token: string | null) => {
            accessToken = token;
        },

        getAccessToken: () => accessToken,

        /** Get KDF parameters for a user's email before login. */
        preLogin: (email: string): Promise<PreLoginResponse> =>
            jsonPost('/api/accounts/prelogin', { email }),

        /** Authenticate with email + master password hash.
         *  Returns tokens and encrypted symmetric key. */
        login: (params: {
            email: string;
            masterPasswordHash: string;
            deviceIdentifier: string;
            deviceName: string;
            deviceType: number;
            twoFactorToken?: string;
            twoFactorProvider?: number;
            twoFactorRemember?: boolean;
        }): Promise<LoginResponse> =>
            formPost('/identity/connect/token', {
                grant_type: 'password',
                username: params.email,
                password: params.masterPasswordHash,
                scope: 'api offline_access',
                client_id: 'browser',
                deviceType: String(params.deviceType),
                deviceIdentifier: params.deviceIdentifier,
                deviceName: params.deviceName,
                ...(params.twoFactorToken
                    ? {
                          twoFactorToken: params.twoFactorToken,
                          twoFactorProvider: String(params.twoFactorProvider ?? 0),
                          twoFactorRemember: params.twoFactorRemember ? '1' : '0',
                      }
                    : {}),
            }),

        /** Refresh the access token using the refresh token. */
        refreshToken: (refreshToken: string): Promise<RefreshResponse> =>
            formPost('/identity/connect/token', {
                grant_type: 'refresh_token',
                client_id: 'browser',
                refresh_token: refreshToken,
            }),

        /** Fetch the full vault sync (profile, folders, ciphers, domains). */
        sync: (): Promise<SyncResponse> => jsonGet('/api/sync'),

        /** Fetch a single cipher by ID. */
        getCipher: (id: string): Promise<CipherResponse> => jsonGet(`/api/ciphers/${id}`),

        /** Create a new cipher. */
        createCipher: (cipher: Record<string, unknown>): Promise<CipherResponse> =>
            jsonPost('/api/ciphers', cipher),

        /** Update an existing cipher. */
        updateCipher: (id: string, cipher: Record<string, unknown>): Promise<CipherResponse> =>
            jsonPost(`/api/ciphers/${id}`, cipher),

        /** Delete (trash) a cipher. */
        deleteCipher: (id: string): Promise<void> =>
            fetch(`${config.baseUrl}/api/ciphers/${id}`, {
                method: 'DELETE',
                headers: headers(),
            }).then((res) => {
                if (!res.ok) throw new BitwardenApiError(`DELETE /api/ciphers/${id} failed: ${res.status}`, res.status);
            }),
    };
};

export type BitwardenApi = ReturnType<typeof createBitwardenApi>;
export { createBitwardenApi };
