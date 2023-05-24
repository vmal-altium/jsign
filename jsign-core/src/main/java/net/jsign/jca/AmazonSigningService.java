/**
 * Copyright 2022 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.jsign.jca;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import net.jsign.DigestAlgorithm;

import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.*;

/**
 * Signing service using the AWS API.
 *
 * @since 5.0
 * @see <a href="https://docs.aws.amazon.com/kms/latest/APIReference/">AWS Key Management Service API Reference</a>
 * @see <a href="https://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html">Signing AWS API Requests</a>
 */
public class AmazonSigningService implements SigningService {

    /** Source for the certificates */
    private final Function<String, Certificate[]> certificateStore;

    /** Cache of private keys indexed by id */
    private final Map<String, SigningServicePrivateKey> keys = new HashMap<>();

    private final KmsClient kms;

    /** Mapping between Java and AWS signing algorithms */
    private final Map<String, String> algorithmMapping = new HashMap<>();
    {
        algorithmMapping.put("SHA256withRSA", "RSASSA_PKCS1_V1_5_SHA_256");
        algorithmMapping.put("SHA384withRSA", "RSASSA_PKCS1_V1_5_SHA_384");
        algorithmMapping.put("SHA512withRSA", "RSASSA_PKCS1_V1_5_SHA_512");
        algorithmMapping.put("SHA256withECDSA", "ECDSA_SHA_256");
        algorithmMapping.put("SHA384withECDSA", "ECDSA_SHA_384");
        algorithmMapping.put("SHA512withECDSA", "ECDSA_SHA_512");
        algorithmMapping.put("SHA256withRSA/PSS", "RSASSA_PSS_SHA_256");
        algorithmMapping.put("SHA384withRSA/PSS", "RSASSA_PSS_SHA_384");
        algorithmMapping.put("SHA512withRSA/PSS", "RSASSA_PSS_SHA_512");
    }

    /**
     * Creates a new AWS signing service.
     *
     * @param region           the AWS region holding the keys (for example <tt>eu-west-3</tt>)
     * @param credentials      the AWS credentials: <tt>accessKey|secretKey|sessionToken</tt> (the session token is optional)
     * @param certificateStore provides the certificate chain for the keys
     */
    public AmazonSigningService(String region, String credentials, Function<String, Certificate[]> certificateStore) {
        this.certificateStore = certificateStore;
        KmsClientBuilder kmsClientBuilder = KmsClient.builder()
                .region(Region.of(region))
                .httpClientBuilder(UrlConnectionHttpClient.builder());

        if (credentials != null) {
            // parse the credentials
            String[] elements = credentials.split("\\|", 3);
            if (elements.length < 2) {
                throw new IllegalArgumentException("Invalid AWS credentials: " + credentials);
            }
            String accessKey = elements[0];
            String secretKey = elements[1];
            String sessionToken = elements.length > 2 ? elements[2] : null;
            AwsCredentials awsCredentials = sessionToken != null
                    ? AwsSessionCredentials.create(accessKey, secretKey, sessionToken)
                    : AwsBasicCredentials.create(accessKey, secretKey);
            kmsClientBuilder = kmsClientBuilder.credentialsProvider(StaticCredentialsProvider.create(awsCredentials));
        }
        this.kms = kmsClientBuilder.build();
    }

    @Override
    public String getName() {
        return "AWS";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        List<String> aliases = new ArrayList<>();

        try {
            // kms:ListKeys (https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html)
            ListKeysResponse response = kms.listKeys();
            List<KeyListEntry> keys =  response.keys();
            for (KeyListEntry key : keys) {
                aliases.add(key.keyId());
            }
        } catch (SdkException e) {
            throw new KeyStoreException(e);
        }

        return aliases;
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        return certificateStore.apply(alias);
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        if (keys.containsKey(alias)) {
            return keys.get(alias);
        }

        String algorithm;

        try {
            // kms:DescribeKey (https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html)
            DescribeKeyResponse response = kms.describeKey(DescribeKeyRequest.builder().keyId(normalizeKeyId(alias)).build());
            KeyMetadata keyMetadata = response.keyMetadata();

            String keyUsage = keyMetadata.keyUsageAsString();
            if (!"SIGN_VERIFY".equals(keyUsage)) {
                throw new UnrecoverableKeyException("The key '" + alias + "' is not a signing key");
            }

            String keyState = keyMetadata.keyStateAsString();
            if (!"Enabled".equals(keyState)) {
                throw new UnrecoverableKeyException("The key '" + alias + "' is not enabled (" + keyState + ")");
            }

            String keySpec = keyMetadata.keySpecAsString();
            algorithm = keySpec.substring(0, keySpec.indexOf('_'));
        } catch (SdkException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch AWS key '" + alias + "'").initCause(e);
        }

        SigningServicePrivateKey key = new SigningServicePrivateKey(alias, algorithm);
        keys.put(alias, key);
        return key;
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        String alg = algorithmMapping.get(algorithm);
        if (alg == null) {
            throw new InvalidAlgorithmParameterException("Unsupported signing algorithm: " + algorithm);
        }

        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        data = digestAlgorithm.getMessageDigest().digest(data);

        try {
            // kms:Sign (https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)
            SignResponse response = kms.sign(SignRequest.builder()
                    .keyId(normalizeKeyId(privateKey.getId()))
                    .messageType(MessageType.DIGEST)
                    .message(SdkBytes.fromByteArray(data))
                    .signingAlgorithm(alg)
                    .build());
            return response.signature().asByteArray();
        } catch (SdkException e) {
            throw new GeneralSecurityException(e);
        }
    }

    /**
     * Prefixes the key id with <tt>alias/</tt> if necessary.
     */
    private String normalizeKeyId(String keyId) {
        if (keyId.startsWith("arn:") || keyId.startsWith("alias/")) {
            return keyId;
        }

        if (!keyId.matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")) {
            return "alias/" + keyId;
        } else {
            return keyId;
        }
    }
}
