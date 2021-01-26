package com.doroshenko.serhey.auth.service.crypto;

import com.doroshenko.serhey.lib.core.service.crypto.KeyPairService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.keys.KeyManager;
import org.springframework.security.crypto.keys.ManagedKey;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class CustomKeyGeneratingKeyManager implements KeyManager {

    private final Map<String, ManagedKey> keys = new HashMap<>();

    @Autowired
    public CustomKeyGeneratingKeyManager(final KeyPairService keyPairService) {
        final ManagedKey managedKey = ManagedKey.withAsymmetricKey(
                keyPairService.loadPublicKey(),
                keyPairService.loadPrivateKey()
        ).keyId(UUID.randomUUID().toString()).activatedOn(Instant.now()).build();
        keys.put(managedKey.getKeyId(), managedKey);
    }

    @Override
    public ManagedKey findByKeyId(String keyId) {
        Assert.hasText(keyId, "keyId cannot be empty");
        return this.keys.get(keyId);
    }

    @Override
    public Set<ManagedKey> findByAlgorithm(String algorithm) {
        Assert.hasText(algorithm, "algorithm cannot be empty");
        return this.keys.values().stream()
                .filter(managedKey -> managedKey.getAlgorithm().equals(algorithm))
                .collect(Collectors.toSet());
    }

    @Override
    public Set<ManagedKey> getKeys() {
        return new HashSet<>(this.keys.values());
    }

}
