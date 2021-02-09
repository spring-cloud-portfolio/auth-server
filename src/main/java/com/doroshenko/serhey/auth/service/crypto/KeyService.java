package com.doroshenko.serhey.auth.service.crypto;

import com.doroshenko.serhey.lib.core.service.crypto.KeyPairService;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Service
public class KeyService {

    private final KeyPairService keyPairService;

    @Autowired
    public KeyService(final KeyPairService keyPairService) {
        this.keyPairService = keyPairService;
    }

    public RSAKey getRsaKey() {
        final RSAPublicKey publicKey = (RSAPublicKey) keyPairService.loadPublicKey();
        final RSAPrivateKey privateKey = (RSAPrivateKey) keyPairService.loadPrivateKey();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

}
