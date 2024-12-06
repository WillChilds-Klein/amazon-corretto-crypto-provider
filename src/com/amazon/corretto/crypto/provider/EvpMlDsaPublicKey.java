package com.amazon.corretto.crypto.provider;

import java.security.PublicKey;

class EvpMlDsaPublicKey extends EvpMlDsaKey implements PublicKey {
    EvpMlDsaPublicKey(final InternalKey key) {
        super(key, true);
    }
}
