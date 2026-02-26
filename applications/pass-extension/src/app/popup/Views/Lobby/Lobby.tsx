import { type FC, useCallback, useState } from 'react';

import { popupMessage, sendMessage } from 'proton-pass-extension/lib/message/send-message';
import { WorkerMessageType } from 'proton-pass-extension/types/messages';

import { Button } from '@proton/atoms/Button/Button';
import { CircleLoader } from '@proton/atoms/CircleLoader/CircleLoader';
import { useAppState } from '@proton/pass/components/Core/AppStateProvider';
import { LobbyLayout } from '@proton/pass/components/Layout/Lobby/LobbyLayout';
import { clientBusy, clientErrored } from '@proton/pass/lib/client';
import { AppStatus } from '@proton/pass/types';

export const Lobby: FC = () => {
    const state = useAppState();
    const busy = clientBusy(state.status);
    const errored = clientErrored(state.status);

    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [twoFactor, setTwoFactor] = useState('');
    const [showTwoFactor, setShowTwoFactor] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleLogin = useCallback(async () => {
        if (!email || !password) return;

        setLoading(true);
        setError(null);

        try {
            const response = await sendMessage(
                popupMessage({
                    type: WorkerMessageType.BITWARDEN_LOGIN,
                    payload: {
                        email,
                        password,
                        ...(showTwoFactor && twoFactor
                            ? { twoFactorToken: twoFactor, twoFactorProvider: 0 }
                            : {}),
                    },
                })
            );

            if (!response.ok) {
                if (response.error?.includes('Two-factor')) {
                    setShowTwoFactor(true);
                    setError('Enter your two-factor authentication code');
                } else {
                    setError(response.error || 'Login failed');
                }
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Login failed');
        } finally {
            setLoading(false);
        }
    }, [email, password, twoFactor, showTwoFactor]);

    const handleKeyDown = useCallback(
        (e: React.KeyboardEvent) => {
            if (e.key === 'Enter') handleLogin();
        },
        [handleLogin]
    );

    if (busy) {
        return (
            <LobbyLayout>
                <div className="flex flex-column items-center gap-3 mt-12 w-full anime-fade-in">
                    <CircleLoader size="medium" />
                    <span className="block text-sm text-weak">
                        {state.status === AppStatus.AUTHORIZING
                            ? 'Signing you in'
                            : state.status === AppStatus.BOOTING
                              ? 'Decrypting your data'
                              : 'Loading BastionPass'}
                    </span>
                </div>
            </LobbyLayout>
        );
    }

    return (
        <LobbyLayout>
            <div className="anime-fade-in" style={{ '--anime-delay': '250ms' } as React.CSSProperties}>
                <div className="flex flex-column items-center gap-3">
                    <span className="pass-lobby--heading w-full text-bold text-norm text-no-wrap flex items-end justify-center user-select-none">
                        BastionPass
                    </span>
                    <span className="text-norm text-sm">Sign in to your vault</span>
                </div>

                {error && (
                    <div className="mt-4 p-3 rounded bg-danger color-invert text-sm">
                        {error}
                    </div>
                )}

                <div className="flex flex-column gap-2 mt-6">
                    <input
                        type="email"
                        placeholder="Email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        onKeyDown={handleKeyDown}
                        autoFocus
                        className="w-full p-3 rounded border border-weak bg-norm text-norm"
                        style={{ outline: 'none', fontSize: '14px' }}
                    />

                    <input
                        type="password"
                        placeholder="Master password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        onKeyDown={handleKeyDown}
                        className="w-full p-3 rounded border border-weak bg-norm text-norm"
                        style={{ outline: 'none', fontSize: '14px' }}
                    />

                    {showTwoFactor && (
                        <input
                            type="text"
                            placeholder="Two-factor code"
                            value={twoFactor}
                            onChange={(e) => setTwoFactor(e.target.value)}
                            onKeyDown={handleKeyDown}
                            autoFocus
                            className="w-full p-3 rounded border border-weak bg-norm text-norm"
                            style={{ outline: 'none', fontSize: '14px' }}
                        />
                    )}

                    <Button
                        pill
                        shape="solid"
                        color="norm"
                        className="w-full mt-2"
                        onClick={handleLogin}
                        disabled={loading || !email || !password}
                    >
                        {loading ? <CircleLoader size="small" /> : 'Sign in'}
                    </Button>
                </div>
            </div>
        </LobbyLayout>
    );
};
