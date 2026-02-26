/**
 * SimpleLogin API client for self-hosted instances.
 *
 * Talks directly to the SimpleLogin REST API instead of going
 * through Proton's pass/v1/ proxy. Used for alias creation,
 * listing, toggling, and mailbox management.
 *
 * Auth: `Authentication: <api_key>` header on every request.
 * Docs: https://github.com/simple-login/app (self-hosted)
 */

export type SLMailbox = {
    id: number;
    email: string;
    verified: boolean;
    default: boolean;
    nb_alias: number;
};

export type SLSuffix = {
    suffix: string;
    signed_suffix: string;
    is_custom: boolean;
    is_premium: boolean;
    domain: string;
};

export type SLAliasOptions = {
    can_create: boolean;
    suffixes: SLSuffix[];
    mailboxes: SLMailbox[];
};

export type SLAlias = {
    id: number;
    email: string;
    name: string | null;
    enabled: boolean;
    creation_date: string;
    creation_timestamp: number;
    nb_forward: number;
    nb_block: number;
    nb_reply: number;
    note: string | null;
    mailbox: { id: number; email: string };
    mailboxes: { id: number; email: string }[];
    support_pgp: boolean;
    latest_activity: { action: string; timestamp: number; contact: { email: string } } | null;
    pinned: boolean;
};

export type SLCreateAliasRequest = {
    alias_prefix: string;
    signed_suffix: string;
    mailbox_ids: number[];
    name?: string;
    note?: string;
};

export type SimpleLoginConfig = {
    baseUrl: string;
    apiKey: string;
};

export class SimpleLoginApiError extends Error {
    constructor(
        public status: number,
        message: string
    ) {
        super(message);
        this.name = 'SimpleLoginApiError';
    }
}

const request = async <T>(config: SimpleLoginConfig, path: string, options: RequestInit = {}): Promise<T> => {
    const url = `${config.baseUrl.replace(/\/$/, '')}/api${path}`;

    const response = await fetch(url, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            Authentication: config.apiKey,
            ...options.headers,
        },
    });

    if (!response.ok) {
        const body = await response.text().catch(() => '');
        let message: string;
        try {
            message = JSON.parse(body)?.error || body;
        } catch {
            message = body || `HTTP ${response.status}`;
        }
        throw new SimpleLoginApiError(response.status, message);
    }

    return response.json();
};

export const createSimpleLoginApi = (config: SimpleLoginConfig) => ({
    /** Get available alias options (suffixes + mailboxes). */
    getOptions: (): Promise<SLAliasOptions> =>
        request<SLAliasOptions>(config, '/v5/alias/options'),

    /** Create a new custom alias. */
    createAlias: (data: SLCreateAliasRequest): Promise<SLAlias> =>
        request<SLAlias>(config, '/v3/alias/custom/new', {
            method: 'POST',
            body: JSON.stringify(data),
        }),

    /** List all aliases (paginated). */
    listAliases: (pageId: number = 0): Promise<{ aliases: SLAlias[] }> =>
        request<{ aliases: SLAlias[] }>(config, `/v2/aliases?page_id=${pageId}`),

    /** Toggle alias enabled/disabled. Returns the updated alias. */
    toggleAlias: (aliasId: number): Promise<SLAlias> =>
        request<SLAlias>(config, `/aliases/${aliasId}/toggle`, { method: 'POST' }),

    /** Get alias details by ID. */
    getAlias: (aliasId: number): Promise<SLAlias> =>
        request<SLAlias>(config, `/aliases/${aliasId}`),

    /** Delete an alias permanently. */
    deleteAlias: (aliasId: number): Promise<{ deleted: boolean }> =>
        request<{ deleted: boolean }>(config, `/aliases/${aliasId}`, { method: 'DELETE' }),

    /** List all mailboxes. */
    getMailboxes: (): Promise<{ mailboxes: SLMailbox[] }> =>
        request<{ mailboxes: SLMailbox[] }>(config, '/v2/mailboxes'),

    /** Update alias mailboxes. */
    updateAliasMailboxes: (aliasId: number, mailboxIds: number[]): Promise<SLAlias> =>
        request<SLAlias>(config, `/aliases/${aliasId}`, {
            method: 'PUT',
            body: JSON.stringify({ mailbox_ids: mailboxIds }),
        }),

    /** Update alias name/note. */
    updateAlias: (aliasId: number, data: { name?: string; note?: string }): Promise<SLAlias> =>
        request<SLAlias>(config, `/aliases/${aliasId}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        }),
});

export type SimpleLoginApi = ReturnType<typeof createSimpleLoginApi>;
