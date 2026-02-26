/** Bitwarden/Vaultwarden API types */

export enum KdfType {
    PBKDF2 = 0,
    Argon2id = 1,
}

export type PreLoginResponse = {
    kdf: KdfType;
    kdfIterations: number;
    kdfMemory: number | null;
    kdfParallelism: number | null;
};

export type LoginRequest = {
    email: string;
    masterPasswordHash: string;
    deviceIdentifier: string;
    deviceName: string;
    deviceType: number;
    twoFactorToken?: string;
    twoFactorProvider?: number;
    twoFactorRemember?: boolean;
};

export type LoginResponse = {
    access_token: string;
    expires_in: number;
    token_type: string;
    refresh_token: string;
    scope: string;
    Key: string;
    PrivateKey: string;
    Kdf: KdfType;
    KdfIterations: number;
    KdfMemory: number | null;
    KdfParallelism: number | null;
    ForcePasswordReset: boolean;
    ResetMasterPassword: boolean;
    TwoFactorToken?: string;
    UserDecryptionOptions?: {
        HasMasterPassword: boolean;
    };
};

export type TwoFactorRequired = {
    error: string;
    error_description: string;
    TwoFactorProviders2: Record<string, Record<string, string> | null>;
};

export type RefreshResponse = {
    access_token: string;
    expires_in: number;
    token_type: string;
    refresh_token: string;
};

export enum CipherType {
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4,
    SshKey = 5,
}

export enum EncType {
    AesCbc256 = 0,
    AesCbc256HmacSha256 = 2,
}

export type SyncResponse = {
    /** Vaultwarden returns lowercase top-level keys */
    profile: {
        /** Profile fields are camelCase in Vaultwarden */
        id: string;
        name: string;
        email: string;
        emailVerified: boolean;
        premium: boolean;
        key: string;
        privateKey: string;
        securityStamp: string;
        organizations: {
            id: string;
            name: string;
            key: string;
            enabled: boolean;
        }[];
    };
    folders: {
        /** Folder fields are PascalCase in Vaultwarden */
        Id: string;
        Name: string;
        RevisionDate: string;
    }[];
    ciphers: CipherResponse[];
    domains: {
        EquivalentDomains: string[][];
        GlobalEquivalentDomains: { Type: number; Domains: string[]; Excluded: boolean }[];
    };
};

export type CipherResponse = {
    Id: string;
    OrganizationId: string | null;
    FolderId: string | null;
    Type: CipherType;
    Name: string;
    Notes: string | null;
    Favorite: boolean;
    Reprompt: number;
    Login?: {
        Uris: { Uri: string; Match: number | null }[] | null;
        Username: string | null;
        Password: string | null;
        Totp: string | null;
        Fido2Credentials: unknown[] | null;
    };
    Card?: {
        CardholderName: string | null;
        Brand: string | null;
        Number: string | null;
        ExpMonth: string | null;
        ExpYear: string | null;
        Code: string | null;
    };
    Identity?: Record<string, string | null>;
    SecureNote?: { Type: number };
    Fields: { Name: string | null; Value: string | null; Type: number }[] | null;
    RevisionDate: string;
    CreationDate: string;
    DeletedDate: string | null;
};

/** Decrypted session stored locally in the extension */
export type BitwardenSession = {
    accessToken: string;
    refreshToken: string;
    expiresAt: number;
    kdf: KdfType;
    kdfIterations: number;
    kdfMemory: number | null;
    kdfParallelism: number | null;
    /** The decrypted 64-byte user symmetric key (encKey + macKey) */
    userSymmetricKey: string;
    /** The encrypted RSA private key from the server */
    encryptedPrivateKey: string;
    userEmail: string;
    userId: string;
};
