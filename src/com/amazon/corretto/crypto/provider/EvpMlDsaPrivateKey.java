package com.amazon.corretto.crypto.provider;

import java.security.PrivateKey;

class EvpMlDsaPrivateKey extends EvpMlDsaKey implements PrivateKey {
    EvpMlDsaPrivateKey(final InternalKey key) {
        super(key, false);
    }
    EvpMlDsaPublicKey getPublic() {
        final EvpMlDsaPublicKey result = new EvpMlDsaPublicKey(internalKey);
        ephemeral = false;
        sharedKey = true;
        result.sharedKey = true;
        return result;
    }
}
