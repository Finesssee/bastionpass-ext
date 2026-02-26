/**
 * Alias service for BastionPass.
 *
 * Replaces Proton's alias handlers with direct SimpleLogin API calls.
 * When a user creates an alias:
 *   1. SimpleLogin creates the email alias
 *   2. We create a Bitwarden cipher in Vaultwarden to store it
 *   3. We update the local Redux store so the UI shows it
 */
import WorkerMessageBroker from 'proton-pass-extension/app/worker/channel';
import { onContextReady } from 'proton-pass-extension/app/worker/context/inject';
import { WorkerMessageType } from 'proton-pass-extension/types/messages';

import {
    createBitwardenApi,
    createSimpleLoginApi,
    encryptToEncString,
    type SimpleLoginConfig,
} from '@proton/pass/lib/auth/bitwarden';
import { bootSuccess } from '@proton/pass/store/actions/creators/client';
import type { AliasMailbox, AliasOptions } from '@proton/pass/types/data/alias';
import { obfuscate } from '@proton/pass/utils/obfuscate/xor';
import { logger } from '@proton/pass/utils/logger';

/** Encrypt a plain string to a Bitwarden EncString using stored keys. */
const encryptField = async (value: string, encKey: ArrayBuffer, macKey: ArrayBuffer): Promise<string> => {
    const data = new TextEncoder().encode(value).buffer;
    return encryptToEncString(data, encKey, macKey);
};

/** Derive enc/mac keys from stored BW session symmetric key. */
const getKeysFromSession = (session: { userSymmetricKey: string }): { encKey: ArrayBuffer; macKey: ArrayBuffer } => {
    const keyBytes = Uint8Array.from(atob(session.userSymmetricKey), (c) => c.charCodeAt(0));
    return {
        encKey: keyBytes.slice(0, 32).buffer,
        macKey: keyBytes.slice(32, 64).buffer,
    };
};

export const createAliasService = () => {
    /** Resolve SimpleLogin config from extension storage. */
    const getSLConfig = async (ctx: any): Promise<SimpleLoginConfig | null> => {
        const config = await ctx.service.storage.local.getItem('sl_config');
        if (!config) return null;
        const parsed = typeof config === 'string' ? JSON.parse(config) : config;
        if (!parsed?.baseUrl || !parsed?.apiKey) return null;
        return parsed;
    };

    WorkerMessageBroker.registerMessage(
        WorkerMessageType.ALIAS_OPTIONS,
        onContextReady(async (ctx) => {
            const slConfig = await getSLConfig(ctx);
            if (!slConfig) {
                return { ok: false, error: 'SimpleLogin not configured. Set your API key in settings.' };
            }

            try {
                const sl = createSimpleLoginApi(slConfig);
                const slOptions = await sl.getOptions();

                const options: AliasOptions = {
                    suffixes: slOptions.suffixes.map((s) => ({
                        suffix: s.suffix,
                        signedSuffix: s.signed_suffix,
                        isPremium: s.is_premium,
                        isCustom: s.is_custom,
                        domain: s.domain,
                    })),
                    mailboxes: slOptions.mailboxes.map((m): AliasMailbox => ({
                        id: m.id,
                        email: m.email,
                    })),
                };

                return { ok: true, needsUpgrade: false, options };
            } catch (error) {
                logger.warn('[AliasService] Failed to fetch alias options', error);
                const message = error instanceof Error ? error.message : 'Failed to fetch alias options';
                return { ok: false, error: message };
            }
        })
    );

    WorkerMessageBroker.registerMessage(
        WorkerMessageType.ALIAS_CREATE,
        onContextReady(async (ctx, message) => {
            const slConfig = await getSLConfig(ctx);
            if (!slConfig) {
                return { ok: false, error: 'SimpleLogin not configured.' };
            }

            const bwSessionStr = await ctx.service.storage.local.getItem('bw_session');
            if (!bwSessionStr) {
                return { ok: false, error: 'Not logged in to Vaultwarden.' };
            }

            const bwSession = JSON.parse(bwSessionStr as string);

            try {
                const sl = createSimpleLoginApi(slConfig);
                const { origin: url, alias } = message.payload;
                const { mailboxes, prefix, aliasEmail } = alias;

                // 1. Create the alias in SimpleLogin
                const slAlias = await sl.createAlias({
                    alias_prefix: prefix,
                    signed_suffix: alias.signedSuffix,
                    mailbox_ids: mailboxes.map((m: AliasMailbox) => m.id),
                    name: url,
                    note: `Created from BastionPass for ${url}`,
                });

                logger.info(`[AliasService] Created alias: ${slAlias.email}`);

                // 2. Create a Bitwarden cipher for this alias
                const { encKey, macKey } = getKeysFromSession(bwSession);
                const bwApi = createBitwardenApi({ baseUrl: 'https://vault.southernwind.xyz' });
                bwApi.setAccessToken(bwSession.accessToken);

                const encName = await encryptField(url || slAlias.email, encKey, macKey);
                const encNotes = await encryptField(`Alias created for ${url}`, encKey, macKey);
                const encUsername = await encryptField(slAlias.email, encKey, macKey);

                const cipher = await bwApi.createCipher({
                    type: 1, // Login
                    name: encName,
                    notes: encNotes,
                    login: {
                        username: encUsername,
                        password: null,
                        totp: null,
                        uris: url
                            ? [{ uri: await encryptField(url, encKey, macKey), match: null }]
                            : [],
                    },
                    folderId: null,
                    organizationId: null,
                    favorite: false,
                });

                // 3. Add the item to the local Redux store
                const shareId = 'bw-default-vault';
                const now = Math.floor(Date.now() / 1000);

                const newItem = {
                    itemId: cipher.Id,
                    shareId,
                    revision: 1,
                    contentFormatVersion: 1,
                    state: 1, // Active
                    createTime: now,
                    modifyTime: now,
                    revisionTime: now,
                    lastUseTime: null,
                    pinned: false,
                    flags: 0,
                    aliasEmail: slAlias.email,
                    shareCount: undefined,
                    data: {
                        type: 'login',
                        metadata: {
                            name: url || slAlias.email,
                            note: obfuscate(`Alias created for ${url}`),
                            itemUuid: cipher.Id,
                        },
                        content: {
                            itemEmail: obfuscate(slAlias.email),
                            itemUsername: obfuscate(''),
                            password: obfuscate(''),
                            totpUri: obfuscate(''),
                            urls: url ? [url] : [],
                            passkeys: [],
                        },
                        extraFields: [],
                        platformSpecific: undefined,
                    },
                };

                // Merge into existing state via bootSuccess (additive)
                const state = ctx.service.store.getState();
                const existingShares = state.shares ?? {};
                const existingItems = state.items ?? {};

                const updatedItems = { ...existingItems };
                updatedItems[shareId] = { ...(updatedItems[shareId] ?? {}), [cipher.Id]: newItem };

                ctx.service.store.dispatch(bootSuccess({ shares: existingShares, items: updatedItems }));

                logger.info(`[AliasService] Alias cipher created: ${cipher.Id}`);
                return { ok: true };
            } catch (error) {
                logger.warn('[AliasService] Failed to create alias', error);
                const errorMsg = error instanceof Error ? error.message : 'Failed to create alias';
                return { ok: false, error: errorMsg };
            }
        })
    );

    // SimpleLogin config (get/set)
    WorkerMessageBroker.registerMessage(
        WorkerMessageType.SIMPLELOGIN_CONFIG,
        onContextReady(async (ctx, message) => {
            const payload = message.payload as any;

            // GET mode
            if (payload.get) {
                const config = await getSLConfig(ctx);
                if (config) {
                    return { ok: true, baseUrl: config.baseUrl, apiKey: config.apiKey };
                }
                return { ok: true, baseUrl: '', apiKey: '' };
            }

            // SET mode
            const { baseUrl, apiKey } = payload;
            await ctx.service.storage.local.setItem('sl_config', JSON.stringify({ baseUrl, apiKey }));
            logger.info(`[AliasService] SimpleLogin config saved: ${baseUrl}`);
            return { ok: true, baseUrl, apiKey };
        })
    );

    return {};
};

export type AliasService = ReturnType<typeof createAliasService>;
