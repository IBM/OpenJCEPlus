/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.security.MessageDigest;
import java.util.Arrays;

public class BaseTestSHA512_224 extends BaseTestMessageDigestClone {

    // Test vectors obtained from
    // http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA512_224.pdf

    public BaseTestSHA512_224(String providerName) {
        super(providerName, "SHA-512/224");
    }

    public void testSHA512_224_SingleBlock() throws Exception {

        MessageDigest md = MessageDigest.getInstance(this.algorithm, providerName);

        assertTrue(Arrays.equals(md.digest("abc".getBytes("UTF-8")),
                hexStrToBytes("4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA")));

    }

    public void testSHA512_224_TwoBlock() throws Exception {

        MessageDigest md = MessageDigest.getInstance(this.algorithm, providerName);
        assertTrue(Arrays.equals(
                md.digest(("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                        + "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
                                .getBytes("UTF-8")),
                hexStrToBytes("23FEC5BB94D60B23308192640B0C453335D664734FE40E7268674AF9")));

    }

    public void testSHA512_224_varmsgs() throws Exception {

        String[] calculatedDigests = {"6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4", //0
                "8a18ce99573f3c3436c07301578e7fccf474cc28c8d5e92e47e319b8", //1
                "603bf24627e47691e1d778e976b2719a56d810edafa0a1631d95f821", //2
                "f824af66447e96ccf029d48c479b6ee12ab5e1d0d2f915b9d84d36d7", //3
                "d4656b97c8440f6262174ab429baa45c3126292bd0b37521b1fb1221", //4
                "79721e44c3501864edfb877b80107e0e235163827115faf1eddc3f1c", //5
                "b9247e920d6ab0b76735d488138ab7d6743dd33380d182c885bdc2cf", //6
                "7f8b35cb910b12750d70de1da8c39678ae733cb38fb590df2b3c6182", //7
                "ab12a705621af00fd85fa2b5631ff4a1083817838c69c9ac10a73f4e", //8
                "224a965f8f9b6ed2e96054923f026a69f99e213665c1cb6214ffa040"};


        String msg = "";
        int j = 0;
        MessageDigest mdIBM = MessageDigest.getInstance(this.algorithm, providerName);

        for (int i = 0; i < 10000; i++) {

            byte[] ibmDigest = mdIBM.digest(msg.getBytes("UTF-8"));

            if (i % 1000 == 0) {
                assertTrue(Arrays.equals(hexStrToBytes(calculatedDigests[j]), ibmDigest));
                j = j + 1;
            }
            msg = msg + String.valueOf(i);

        }


    }



    public void testSHA512_224_withUpdates() throws Exception {

        String calcDigest = "367f4e38fba70b22c8d975e1079b5f9f8b3ac971e2ef049c704b1132";

        MessageDigest mdIBM = MessageDigest.getInstance(this.algorithm, providerName);
        String msgarrays[] = {"Hello0", "Hello1", "Hello2", "Hello3", "Hello4", "longmessage5",
                "longermessage6,", "verylongmessage7"};
        for (int i = 0; i < msgarrays.length; i++) {
            mdIBM.update(msgarrays[i].getBytes("UTF-8"));
        }

        byte[] ibmDigest = mdIBM.digest();
        assertTrue(Arrays.equals(hexStrToBytes(calcDigest), ibmDigest));

    }

    static byte[] hexStrToBytes(String in) {
        int len = in.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) Integer.parseInt(in.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

}
