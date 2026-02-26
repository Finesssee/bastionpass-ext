/**
 * Bitwarden → Proton Pass data adapter.
 *
 * Translates Bitwarden sync data (folders + ciphers) into the
 * SynchronizationResult format expected by the Pass Redux store.
 *
 * Mapping:
 *   Bitwarden Folder  → Pass Share (vault)
 *   Bitwarden Cipher   → Pass ItemRevision
 *   No folder (null)   → Default "My Vault" share
 */
import { obfuscate } from '@proton/pass/utils/obfuscate/xor';

import { decryptEncString } from './crypto';
import type { CipherResponse, SyncResponse } from './types';
import { CipherType } from './types';

const DEFAULT_SHARE_ID = 'bw-default-vault';
const DEFAULT_VAULT_NAME = 'My Vault';

/** Decrypt a Bitwarden EncString, returning empty string on failure. */
const tryDecrypt = async (
    encString: string | null | undefined,
    encKey: ArrayBuffer,
    macKey: ArrayBuffer
): Promise<string> => {
    if (!encString) return '';
    try {
        const decrypted = await decryptEncString(encString, encKey, macKey);
        return new TextDecoder().decode(decrypted);
    } catch {
        return '';
    }
};

/** Convert ISO date string to epoch seconds. */
const toEpoch = (iso: string | null | undefined): number => {
    if (!iso) return Math.floor(Date.now() / 1000);
    return Math.floor(new Date(iso).getTime() / 1000);
};

/** Build the share (vault) map from Bitwarden folders. */
export const buildShares = async (
    syncData: SyncResponse,
    encKey: ArrayBuffer,
    macKey: ArrayBuffer
): Promise<Record<string, any>> => {
    const shares: Record<string, any> = {};

    // Default vault for items with no folder
    shares[DEFAULT_SHARE_ID] = {
        shareId: DEFAULT_SHARE_ID,
        vaultId: DEFAULT_SHARE_ID,
        targetId: DEFAULT_SHARE_ID,
        targetType: 1, // ShareType.Vault
        content: {
            name: DEFAULT_VAULT_NAME,
            description: '',
            display: { icon: 0, color: 0 },
        },
        owner: true,
        shared: false,
        shareRoleId: '1', // MANAGER
        createTime: Math.floor(Date.now() / 1000),
        newUserInvitesReady: 0,
        targetMaxMembers: 0,
        targetMembers: 1,
        permission: 0,
        flags: 0,
        canAutofill: true,
        eventId: '',
        addressId: undefined,
        groupId: null,
    };

    // Map each Bitwarden folder to a Pass share
    for (const folder of syncData.folders) {
        const name = await tryDecrypt(folder.Name, encKey, macKey);
        const shareId = `bw-folder-${folder.Id}`;

        shares[shareId] = {
            shareId,
            vaultId: shareId,
            targetId: shareId,
            targetType: 1, // ShareType.Vault
            content: {
                name: name || 'Unnamed Folder',
                description: '',
                display: { icon: 0, color: 0 },
            },
            owner: true,
            shared: false,
            shareRoleId: '1',
            createTime: toEpoch(folder.RevisionDate),
            newUserInvitesReady: 0,
            targetMaxMembers: 0,
            targetMembers: 1,
            permission: 0,
            flags: 0,
            canAutofill: true,
            eventId: '',
            addressId: undefined,
            groupId: null,
        };
    }

    return shares;
};

/** Map a Bitwarden folder ID to a Pass share ID. */
const mapShareId = (folderId: string | null): string => (folderId ? `bw-folder-${folderId}` : DEFAULT_SHARE_ID);

/** Build a Pass ItemRevision from a decrypted Bitwarden cipher. */
const buildLoginItem = (
    cipher: CipherResponse,
    shareId: string,
    name: string,
    notes: string,
    username: string,
    password: string,
    uris: string[],
    totp: string
): any => ({
    itemId: cipher.Id,
    shareId,
    revision: 1,
    contentFormatVersion: 1,
    state: cipher.DeletedDate ? 2 : 1, // Trashed or Active
    createTime: toEpoch(cipher.CreationDate),
    modifyTime: toEpoch(cipher.RevisionDate),
    revisionTime: toEpoch(cipher.RevisionDate),
    lastUseTime: null,
    pinned: cipher.Favorite,
    flags: 0,
    aliasEmail: null,
    shareCount: undefined,
    data: {
        type: 'login',
        metadata: {
            name,
            note: obfuscate(notes),
            itemUuid: cipher.Id,
        },
        content: {
            itemEmail: obfuscate(username),
            itemUsername: obfuscate(''),
            password: obfuscate(password),
            totpUri: obfuscate(totp),
            urls: uris,
            passkeys: [],
        },
        extraFields: [],
        platformSpecific: undefined,
    },
});

const buildNoteItem = (cipher: CipherResponse, shareId: string, name: string, notes: string): any => ({
    itemId: cipher.Id,
    shareId,
    revision: 1,
    contentFormatVersion: 1,
    state: cipher.DeletedDate ? 2 : 1,
    createTime: toEpoch(cipher.CreationDate),
    modifyTime: toEpoch(cipher.RevisionDate),
    revisionTime: toEpoch(cipher.RevisionDate),
    lastUseTime: null,
    pinned: cipher.Favorite,
    flags: 0,
    aliasEmail: null,
    shareCount: undefined,
    data: {
        type: 'note',
        metadata: {
            name,
            note: obfuscate(notes),
            itemUuid: cipher.Id,
        },
        content: {},
        extraFields: [],
        platformSpecific: undefined,
    },
});

const buildCreditCardItem = (
    cipher: CipherResponse,
    shareId: string,
    name: string,
    notes: string,
    card: { cardholderName: string; number: string; expMonth: string; expYear: string; code: string }
): any => ({
    itemId: cipher.Id,
    shareId,
    revision: 1,
    contentFormatVersion: 1,
    state: cipher.DeletedDate ? 2 : 1,
    createTime: toEpoch(cipher.CreationDate),
    modifyTime: toEpoch(cipher.RevisionDate),
    revisionTime: toEpoch(cipher.RevisionDate),
    lastUseTime: null,
    pinned: cipher.Favorite,
    flags: 0,
    aliasEmail: null,
    shareCount: undefined,
    data: {
        type: 'creditCard',
        metadata: {
            name,
            note: obfuscate(notes),
            itemUuid: cipher.Id,
        },
        content: {
            cardholderName: card.cardholderName,
            number: obfuscate(card.number),
            expirationDate: `${card.expYear}-${(card.expMonth || '').padStart(2, '0')}`,
            verificationNumber: obfuscate(card.code),
            pin: obfuscate(''),
            cardType: 0,
        },
        extraFields: [],
        platformSpecific: undefined,
    },
});

/** Build custom fields from Bitwarden fields. */
const buildExtraFields = (fields: CipherResponse['Fields']): any[] => {
    if (!fields) return [];
    return fields.map((field) => ({
        fieldName: field.Name || '',
        type: field.Type === 1 ? 'hidden' : 'text',
        data: { content: obfuscate(field.Value || '') },
    }));
};

/** Main adapter: decrypt all ciphers and build the SynchronizationResult. */
export const adaptBitwardenSync = async (
    syncData: SyncResponse,
    encKey: ArrayBuffer,
    macKey: ArrayBuffer
): Promise<{ shares: Record<string, any>; items: Record<string, Record<string, any>> }> => {
    const shares = await buildShares(syncData, encKey, macKey);

    // Initialize items map with empty objects for each share
    const items: Record<string, Record<string, any>> = {};
    for (const shareId of Object.keys(shares)) {
        items[shareId] = {};
    }

    // Process each cipher
    for (const cipher of syncData.ciphers) {
        const shareId = mapShareId(cipher.FolderId);
        if (!items[shareId]) items[shareId] = {};

        // Decrypt common fields
        const name = await tryDecrypt(cipher.Name, encKey, macKey);
        const notes = await tryDecrypt(cipher.Notes, encKey, macKey);

        let item: any;

        switch (cipher.Type) {
            case CipherType.Login: {
                const login = cipher.Login;
                const username = await tryDecrypt(login?.Username, encKey, macKey);
                const password = await tryDecrypt(login?.Password, encKey, macKey);
                const totp = await tryDecrypt(login?.Totp, encKey, macKey);

                const uris: string[] = [];
                if (login?.Uris) {
                    for (const uri of login.Uris) {
                        const decryptedUri = await tryDecrypt(uri.Uri, encKey, macKey);
                        if (decryptedUri) uris.push(decryptedUri);
                    }
                }

                item = buildLoginItem(cipher, shareId, name, notes, username, password, uris, totp);
                item.data.extraFields = buildExtraFields(cipher.Fields);
                break;
            }

            case CipherType.SecureNote: {
                item = buildNoteItem(cipher, shareId, name, notes);
                break;
            }

            case CipherType.Card: {
                const card = cipher.Card;
                const cardholderName = await tryDecrypt(card?.CardholderName, encKey, macKey);
                const number = await tryDecrypt(card?.Number, encKey, macKey);
                const expMonth = await tryDecrypt(card?.ExpMonth, encKey, macKey);
                const expYear = await tryDecrypt(card?.ExpYear, encKey, macKey);
                const code = await tryDecrypt(card?.Code, encKey, macKey);

                item = buildCreditCardItem(cipher, shareId, name, notes, {
                    cardholderName,
                    number,
                    expMonth,
                    expYear,
                    code,
                });
                break;
            }

            case CipherType.Identity: {
                // Map identity as a note for now (Pass identity support is limited)
                item = buildNoteItem(cipher, shareId, name, notes);
                break;
            }

            default: {
                item = buildNoteItem(cipher, shareId, name, notes);
                break;
            }
        }

        items[shareId][cipher.Id] = item;
    }

    return { shares, items };
};
