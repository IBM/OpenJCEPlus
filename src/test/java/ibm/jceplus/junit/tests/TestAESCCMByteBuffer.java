/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import ibm.security.internal.spec.CCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.stream.Stream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Test case for AES/CCM cipher ByteBuffer operations.
 */
@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestAESCCMByteBuffer extends BaseTest {

    @Parameter(0)
    TestProvider provider;

    private static final int AES_KEY_SIZE_128 = 128;
    private static final int AES_KEY_SIZE_256 = 256;
    private static final int CCM_TAG_LENGTH = 128; // bits
    private static final int CCM_TAG_LENGTH_BYTES = CCM_TAG_LENGTH / 8;
    private static final int CCM_IV_LENGTH = 13; // bytes

    /**
     * Enum representing different ByteBuffer test scenarios.
     */
    private enum BufferScenario {
        STANDARD("Standard ByteBuffer"),
        WITH_POSITION("ByteBuffer with position > 0"),
        WITH_LIMIT("ByteBuffer with limit < capacity"),
        SLICED("Sliced ByteBuffer"),
        DIRECT("Direct ByteBuffer");

        private final String description;

        BufferScenario(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
    }

    /**
     * Provides key sizes for parameterized tests.
     */
    private static Stream<Arguments> keySizeProvider() {
        return Stream.of(
            Arguments.of(AES_KEY_SIZE_128),
            Arguments.of(AES_KEY_SIZE_256)
        );
    }

    @ParameterizedTest
    @MethodSource("keySizeProvider")
    public void testStandardByteBuffer(int keySize) throws Exception {
        testByteBufferScenario(keySize, BufferScenario.STANDARD);
    }

    @ParameterizedTest
    @MethodSource("keySizeProvider")
    public void testByteBufferWithPosition(int keySize) throws Exception {
        testByteBufferScenario(keySize, BufferScenario.WITH_POSITION);
    }

    @ParameterizedTest
    @MethodSource("keySizeProvider")
    public void testByteBufferWithLimit(int keySize) throws Exception {
        testByteBufferScenario(keySize, BufferScenario.WITH_LIMIT);
    }

    @ParameterizedTest
    @MethodSource("keySizeProvider")
    public void testSlicedByteBuffer(int keySize) throws Exception {
        testByteBufferScenario(keySize, BufferScenario.SLICED);
    }

    @ParameterizedTest
    @MethodSource("keySizeProvider")
    public void testDirectByteBuffer(int keySize) throws Exception {
        testByteBufferScenario(keySize, BufferScenario.DIRECT);
    }

    @ParameterizedTest
    @MethodSource("keySizeProvider")
    public void testExactSizedOutputBuffer(int keySize) throws Exception {
        SecretKeySpec keySpec = generateKey(keySize);
        byte[] iv = generateIV();
        byte[] aad = generateAAD();
        byte[] plainBytes = generatePlaintext();

        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", getProviderName());
        CCMParameterSpec ccmSpec = new CCMParameterSpec(CCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmSpec);
        cipher.updateAAD(aad);

        ByteBuffer inputBuffer = ByteBuffer.wrap(plainBytes);
        int exactSize = cipher.getOutputSize(plainBytes.length);
        ByteBuffer outputBuffer = ByteBuffer.allocate(exactSize);

        int encryptedLength = cipher.doFinal(inputBuffer, outputBuffer);

        Assertions.assertTrue(encryptedLength > 0, "Encryption should succeed");
        Assertions.assertTrue(encryptedLength <= exactSize,
                "Encrypted length should not exceed buffer capacity");
        Assertions.assertEquals(encryptedLength, outputBuffer.position(),
                "Output buffer position should match encrypted length");
    }

    @ParameterizedTest
    @MethodSource("keySizeProvider")
    public void testByteBufferRemainingVsArrayLength(int keySize) throws Exception {
        SecretKeySpec keySpec = generateKey(keySize);
        byte[] iv = generateIV();
        byte[] aad = generateAAD();
        byte[] plainBytes = "Test data for remaining() vs array().length".getBytes();

        ByteBuffer largeBackingArray = ByteBuffer.allocate(plainBytes.length + 50);
        largeBackingArray.put(plainBytes);
        largeBackingArray.flip();

        byte[] backingArray = largeBackingArray.array();
        for (int i = plainBytes.length; i < backingArray.length; i++) {
            backingArray[i] = (byte) 0xFF;
        }

        Assertions.assertEquals(plainBytes.length, largeBackingArray.remaining(),
                "Buffer remaining should equal data length");
        Assertions.assertTrue(largeBackingArray.array().length > plainBytes.length,
                "Array length should be larger than data");

        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", getProviderName());
        CCMParameterSpec ccmSpec = new CCMParameterSpec(CCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmSpec);
        cipher.updateAAD(aad);

        int correctOutputSize = cipher.getOutputSize(largeBackingArray.remaining());
        ByteBuffer outputBuffer = ByteBuffer.allocate(correctOutputSize);

        int encryptedLength = cipher.doFinal(largeBackingArray, outputBuffer);

        Assertions.assertTrue(encryptedLength > 0, "Encryption should succeed");
        Assertions.assertEquals(correctOutputSize, encryptedLength,
                "Encrypted length should match expected size");
    }

    @ParameterizedTest
    @MethodSource("keySizeProvider")
    public void testAESCCMEmptyBufferEncryption(int keySize) throws Exception {
        SecretKeySpec keySpec = generateKey(keySize);
        byte[] iv = generateIV();
        CCMParameterSpec ccmSpec = new CCMParameterSpec(CCM_TAG_LENGTH, iv);

        Cipher encryptCipher = Cipher.getInstance("AES/CCM/NoPadding", getProviderName());
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmSpec);

        ByteBuffer emptyInputBuffer = ByteBuffer.allocate(0);
        ByteBuffer outputBuffer = ByteBuffer.allocate(encryptCipher.getOutputSize(0));

        int encryptedLength = encryptCipher.doFinal(emptyInputBuffer, outputBuffer);
        Assertions.assertEquals(CCM_TAG_LENGTH_BYTES, encryptedLength,
                "An encrypted empty payload must equal the authentication tag length");

        outputBuffer.flip();
        Cipher decryptCipher = Cipher.getInstance("AES/CCM/NoPadding", getProviderName());
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ccmSpec);

        ByteBuffer decryptBuffer = ByteBuffer.allocate(decryptCipher.getOutputSize(outputBuffer.remaining()));
        int decryptedLength = decryptCipher.doFinal(outputBuffer, decryptBuffer);

        Assertions.assertEquals(0, decryptedLength,
                "Decryption of a purely tagged buffer must yield 0 text bytes");
    }

    @ParameterizedTest
    @MethodSource("keySizeProvider")
    public void testAESCCMDecryptShortBuffer(int keySize) throws Exception {
        SecretKeySpec keySpec = generateKey(keySize);
        byte[] iv = generateIV();
        CCMParameterSpec ccmSpec = new CCMParameterSpec(CCM_TAG_LENGTH, iv);

        Cipher decryptCipher = Cipher.getInstance("AES/CCM/NoPadding", getProviderName());
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ccmSpec);

        byte[] truncatedCiphertext = new byte[CCM_TAG_LENGTH_BYTES - 1];
        ByteBuffer inputBuffer = ByteBuffer.wrap(truncatedCiphertext);
        ByteBuffer outputBuffer = ByteBuffer.allocate(100);

        try {
            decryptCipher.doFinal(inputBuffer, outputBuffer);
            Assertions.fail("Expected BadPaddingException for payload smaller than tag size");
        } catch (BadPaddingException e) {
            // Expected exception - verify the error message
            Assertions.assertEquals("Input too short - need tag", e.getMessage());
        }
    }

    @ParameterizedTest
    @MethodSource("keySizeProvider")
    public void testAESCCMShortOutputBuffer(int keySize) throws Exception {
        SecretKeySpec keySpec = generateKey(keySize);
        byte[] iv = generateIV();
        CCMParameterSpec ccmSpec = new CCMParameterSpec(CCM_TAG_LENGTH, iv);

        Cipher encryptCipher = Cipher.getInstance("AES/CCM/NoPadding", getProviderName());
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmSpec);

        byte[] data = "Verification payload".getBytes();
        ByteBuffer inputBuffer = ByteBuffer.wrap(data);

        int requiredSize = encryptCipher.getOutputSize(data.length);
        ByteBuffer restrictedOutputBuffer = ByteBuffer.allocate(requiredSize - 1);

        try {
            encryptCipher.doFinal(inputBuffer, restrictedOutputBuffer);
            Assertions.fail("Expected ShortBufferException for undersized output target");
        } catch (ShortBufferException e) {
            // Expected exception - verify the error message
            String expectedMessage = "Output buffer too small. Need " + requiredSize +
                    " bytes but only " + (requiredSize - 1) + " available.";
            Assertions.assertEquals(expectedMessage, e.getMessage());
        }
    }

    /**
     * Test a specific ByteBuffer scenario with a given key size.
     */
    private void testByteBufferScenario(int keySize, BufferScenario scenario) throws Exception {
        SecretKeySpec keySpec = generateKey(keySize);
        byte[] iv = generateIV();
        byte[] aad = generateAAD();
        byte[] plainBytes = generatePlaintext();

        ByteBuffer inputBuffer = createBufferForScenario(scenario, plainBytes);

        int startPosition = inputBuffer.position();
        inputBuffer.put(plainBytes);
        inputBuffer.position(startPosition);

        Cipher encryptCipher = Cipher.getInstance("AES/CCM/NoPadding", getProviderName());
        CCMParameterSpec ccmSpec = new CCMParameterSpec(CCM_TAG_LENGTH, iv);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmSpec);
        encryptCipher.updateAAD(aad);

        int outputSize = encryptCipher.getOutputSize(inputBuffer.remaining());
        ByteBuffer outputBuffer = ByteBuffer.allocate(outputSize);

        int encryptedLength = encryptCipher.doFinal(inputBuffer, outputBuffer);

        Assertions.assertTrue(encryptedLength > 0, "Encryption should produce output");
        Assertions.assertEquals(encryptedLength, outputBuffer.position(),
                "Output buffer position should match encrypted length");

        outputBuffer.flip();
        byte[] cipherBytes = new byte[outputBuffer.remaining()];
        outputBuffer.get(cipherBytes);

        Cipher decryptCipher = Cipher.getInstance("AES/CCM/NoPadding", getProviderName());
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ccmSpec);
        decryptCipher.updateAAD(aad);

        ByteBuffer cipherBuffer = ByteBuffer.wrap(cipherBytes);
        int decryptOutputSize = decryptCipher.getOutputSize(cipherBuffer.remaining());
        ByteBuffer decryptBuffer = ByteBuffer.allocate(decryptOutputSize);

        decryptCipher.doFinal(cipherBuffer, decryptBuffer);

        decryptBuffer.flip();
        byte[] decryptedBytes = new byte[decryptBuffer.remaining()];
        decryptBuffer.get(decryptedBytes);
        String decryptedText = new String(decryptedBytes);

        Assertions.assertEquals(new String(plainBytes), decryptedText);
    }

    /**
     * Create a ByteBuffer configured for the specified scenario.
     */
    private ByteBuffer createBufferForScenario(BufferScenario scenario, byte[] plainBytes) {
        SecureRandom secureRandom = new SecureRandom();

        switch (scenario) {
            case STANDARD:
                return ByteBuffer.allocate(plainBytes.length);

            case WITH_POSITION:
                ByteBuffer bufferWithPosition = ByteBuffer.allocate(plainBytes.length + 10);
                byte[] prefixPoison = new byte[5];
                java.util.Arrays.fill(prefixPoison, (byte) 0xFF);
                bufferWithPosition.put(prefixPoison);
                bufferWithPosition.position(5);
                bufferWithPosition.limit(5 + plainBytes.length);
                return bufferWithPosition;

            case WITH_LIMIT:
                ByteBuffer bufferWithLimit = ByteBuffer.allocate(plainBytes.length + 20);
                bufferWithLimit.limit(plainBytes.length);
                byte[] backingArray = bufferWithLimit.array();
                for (int i = plainBytes.length; i < backingArray.length; i++) {
                    backingArray[i] = (byte) 0xFF;
                }
                return bufferWithLimit;

            case SLICED:
                ByteBuffer largeBuffer = ByteBuffer.allocate(plainBytes.length + 30);
                byte[] largePoison = new byte[largeBuffer.capacity()];
                secureRandom.nextBytes(largePoison);
                largeBuffer.put(largePoison);
                largeBuffer.position(10);
                largeBuffer.limit(10 + plainBytes.length);
                return largeBuffer.slice();

            case DIRECT:
                return ByteBuffer.allocateDirect(plainBytes.length);

            default:
                throw new IllegalArgumentException("Unknown scenario: " + scenario);
        }
    }

    private SecretKeySpec generateKey(int keySize) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", getProviderName());
        keyGenerator.init(keySize);
        SecretKey key = keyGenerator.generateKey();
        return new SecretKeySpec(key.getEncoded(), "AES");
    }

    private byte[] generateIV() {
        byte[] iv = new byte[CCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private byte[] generateAAD() {
        byte[] aad = new byte[16];
        new SecureRandom().nextBytes(aad);
        return aad;
    }

    private byte[] generatePlaintext() {
        return "This is test data for ByteBuffer operations with AES/CCM cipher.".getBytes();
    }
}
