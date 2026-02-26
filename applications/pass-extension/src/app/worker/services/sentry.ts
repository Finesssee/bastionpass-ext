import { setSentryEnabled } from '@proton/shared/lib/helpers/sentry';

export const createSentryService = () => {
    /** BastionPass: Sentry disabled — no DSN configured */
    setSentryEnabled(false);
    return { toggle: (_enabled: boolean) => {} };
};

export type SentryService = ReturnType<typeof createSentryService>;
