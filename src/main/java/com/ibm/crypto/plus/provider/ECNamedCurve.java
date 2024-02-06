/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import sun.security.util.DerOutputStream;
import sun.security.util.ObjectIdentifier;

final class ECNamedCurve extends ECGenParameterSpec implements AlgorithmParameterSpec {

    // friendly name for toString() output
    private final String curveName;

    // well known OID
    private final ObjectIdentifier oid;

    // encoded form (as ECNamedCurve identified via OID)
    private final byte[] encoded;

    // internal ECParameterSpec
    private final ECParameterSpec ecps;

    protected ECNamedCurve(String name, ObjectIdentifier oid, EllipticCurve curve, ECPoint g,
            BigInteger n, int h) throws IOException {
        super(name);
        this.curveName = name;
        this.oid = oid;

        ecps = new ECParameterSpec(curve, g, n, h);

        DerOutputStream out = new DerOutputStream();
        out.putOID(oid);
        encoded = out.toByteArray();
    }

    public ECNamedCurve(String name) {
        super(name);
        this.curveName = name;

        ecps = getECParameterSpec(curveName);

        oid = getOIDFromName(curveName);

        if (oid == null) {
            throw new InvalidParameterException(
                    "The algorithm name or OID provided was not recognized or is not supported");
        }

        DerOutputStream out = new DerOutputStream();
        try {
            out.putOID(oid);
            encoded = out.toByteArray();

        } finally {
            try {
                out.close();
            } catch (IOException e) {
            }
        }
    }

    /**
     * Accepts a name and attempts to retrieve the corresponding OID. Null is
     * returned upon failure.
     *
     * @param name
     * @return ObjectIdentifier
     */
    static ObjectIdentifier getOIDFromName(String name) {
        // System.out.println ("getOIDFromName " + name);
        try {

            // This looks like an OID
            if (name.startsWith("1.3.132") || name.startsWith("1.2.840.10045")
                    || name.startsWith("1.3.36.3.3.2.8")) {

                // This isn't a supported OID
                if (oidMap.get(name) == null)
                    throw new IOException();

                return ObjectIdentifier.of(name);
            }
            String foundoid = nameToOIDMap.get(name);

            // This isn't a supported OID
            if (foundoid == null)
                throw new IOException();

            return ObjectIdentifier.of(foundoid);
        } catch (IOException ioe) {
            return null;
        }
    }

    /**
     * Accepts a name or OID to determine if the curve is a FIPS approved curve
     *
     * @param name
     * @return true if this is a FIPS curve
     */
    static boolean isFIPS(String name) {
        // System.out.println ("getOIDFromName " + name);
        try {
            // This looks like an OID
            if (name.startsWith("1.3.132") || name.startsWith("1.2.840.10045")
                    || name.startsWith("1.3.36.3.3.2.8")) {

                // This isn't a supported OID
                if (OIDtoFIPSMap.get(name) == null)
                    throw new IOException();
                return OIDtoFIPSMap.get(name);
            }
            String foundoid = nameToOIDMap.get(name);

            // This isn't a supported OID
            if (foundoid == null)
                throw new IOException();

            return OIDtoFIPSMap.get(foundoid);
        } catch (IOException ioe) {
            return false;
        }
    }

    static ECParameterSpec getECParameterSpec(String name) {
        ECParameterSpec spec = oidMap.get(name);
        return (spec != null) ? spec : nameMap.get(name);
    }

    // Return a NamedCurve for the specified OID or null if unknown.
    static ECParameterSpec getECParameterSpec(ObjectIdentifier oid) {
        return getECParameterSpec(oid.toString());
    }

    public String toString() {
        return curveName + " (" + oid + ")";
    }

    protected static Map<String, ECParameterSpec> getNameMap() {
        return nameMap;
    }

    // private static final Map<String, String> oidToNameMap = new
    // HashMap<String, String>();
    private static final Map<String, String> nameToOIDMap = new HashMap<String, String>();
    private static final Map<String, Boolean> OIDtoFIPSMap = new HashMap<String, Boolean>();
    private static final Map<String, ECParameterSpec> oidMap = new LinkedHashMap<String, ECParameterSpec>();
    private static final Map<String, ECParameterSpec> nameMap = new HashMap<String, ECParameterSpec>();

    // private static final Map<Integer, ECParameterSpec> lengthMap = new
    // HashMap<Integer, ECParameterSpec>();

    private static Pattern SPLIT_PATTERN = Pattern.compile(",|\\[|\\]");

    private static BigInteger bi(String s) {
        return new BigInteger(s, 16);
    }

    private static void add(String name, String soid, int type, String sfield, String a, String b,
            String x, String y, String n, int h, boolean fips) {
        BigInteger p = bi(sfield);
        ECFieldFp fieldp = null;
        ECFieldF2m fieldm = null;
        EllipticCurve curve = null;

        if ((type == P) || (type == PD)) {
            fieldp = new ECFieldFp(p);
            curve = new EllipticCurve(fieldp, bi(a), bi(b));
        } else if ((type == B) || (type == BD)) {
            // OCK supports binary curves
            fieldm = new ECFieldF2m(p.bitLength() - 1, p);
            curve = new EllipticCurve(fieldm, bi(a), bi(b));
        } else {
            throw new ProviderException("Invalid type: " + type);
        }

        ECPoint g = new ECPoint(bi(x), bi(y));

        try {
            ObjectIdentifier oid = ObjectIdentifier.of(soid);
            ECNamedCurve ecnc = new ECNamedCurve(name, oid, curve, g, bi(n), h);
            ECParameterSpec params = ecnc.getECParameterSpec();
            if (oidMap.put(soid, params) != null) {
                throw new ProviderException("Duplication oid: " + soid);
            }
            if (OIDtoFIPSMap.put(soid, fips) != null) {
                throw new ProviderException("Duplication oid: " + soid);
            }
            String[] commonNames = SPLIT_PATTERN.split(name);
            for (String commonName : commonNames) {
                if (nameMap.put(commonName.trim(), params) != null) {
                    throw new ProviderException("Duplication name: " + commonName);
                }
                if (nameToOIDMap.put(commonName.trim(), soid) != null) {
                    throw new ProviderException("Duplication name: " + commonName);
                }
            }
            // int len = field.getFieldSize();
            // if ((type == PD) || (type == BD) || (lengthMap.get(len) == null))
            // {
            // // add entry if none present for this field size or if
            // // the curve is marked as a default curve.
            // lengthMap.put(len, params);
            // }
        } catch (IOException e) {
            throw new ProviderException("Internal error", e);
        }
    }

    private final static int P = 1; // prime curve
    private final static int B = 2; // binary curve
    private final static int PD = 5; // prime curve, mark as default
    private final static int BD = 6; // binary curve, mark as default

    static {
        /* SEC2 prime curves */
        add("secp112r1", "1.3.132.0.6", P, "DB7C2ABF62E35E668076BEAD208B",
                "DB7C2ABF62E35E668076BEAD2088", "659EF8BA043916EEDE8911702B22",
                "09487239995A5EE76B55F9C2F098", "A89CE5AF8724C0A23E0E0FF77500",
                "DB7C2ABF62E35E7628DFAC6561C5", 1, false);

        add("secp112r2", "1.3.132.0.7", P, "DB7C2ABF62E35E668076BEAD208B",
                "6127C24C05F38A0AAAF65C0EF02C", "51DEF1815DB5ED74FCC34C85D709",
                "4BA30AB5E892B4E1649DD0928643", "adcd46f5882e3747def36e956e97",
                "36DF0AAFD8B8D7597CA10520D04B", 4, false);

        add("secp128r1", "1.3.132.0.28", P, "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
                "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC", "E87579C11079F43DD824993C2CEE5ED3",
                "161FF7528B899B2D0C28607CA52C5B86", "CF5AC8395BAFEB13C02DA292DDED7A83",
                "FFFFFFFE0000000075A30D1B9038A115", 1, false);

        add("secp128r2", "1.3.132.0.29", P, "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
                "D6031998D1B3BBFEBF59CC9BBFF9AEE1", "5EEEFCA380D02919DC2C6558BB6D8A5D",
                "7B6AA5D85E572983E6FB32A7CDEBC140", "27B6916A894D3AEE7106FE805FC34B44",
                "3FFFFFFF7FFFFFFFBE0024720613B5A3", 4, false);

        add("secp160k1", "1.3.132.0.9", P, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73",
                "0000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000007",
                "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB",
                "938CF935318FDCED6BC28286531733C3F03C4FEE",
                "0100000000000000000001B8FA16DFAB9ACA16B6B3", 1, false);

        add("secp160r1", "1.3.132.0.8", P, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC",
                "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45",
                "4A96B5688EF573284664698968C38BB913CBFC82",
                "23A628553168947D59DCC912042351377AC5FB32",
                "0100000000000000000001F4C8F927AED3CA752257", 1, false);

        add("secp160r2", "1.3.132.0.30", P, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70",
                "B4E134D3FB59EB8BAB57274904664D5AF50388BA",
                "52DCB034293A117E1F4FF11B30F7199D3144CE6D",
                "FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E",
                "0100000000000000000000351EE786A818F3A1A16B", 1, false);

        add("secp192k1", "1.3.132.0.31", P, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37",
                "000000000000000000000000000000000000000000000000",
                "000000000000000000000000000000000000000000000003",
                "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D",
                "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D",
                "FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", 1, false);

        add("secp192r1 [NIST P-192, X9.62 prime192v1]", "1.2.840.10045.3.1.1", PD,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
                "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
                "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
                "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
                "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 1, true);

        add("secp224k1", "1.3.132.0.32", P,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D",
                "00000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000005",
                "A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C",
                "7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5",
                "010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7", 1, false);

        add("secp224r1 [NIST P-224]", "1.3.132.0.33", PD,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
                "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
                "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
                "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 1, true);

        add("secp256k1", "1.3.132.0.10", P,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000007",
                "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 1, false);

        add("secp256r1 [NIST P-256, X9.62 prime256v1]", "1.2.840.10045.3.1.7", PD,
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
                "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
                "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
                "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 1, true);

        add("secp384r1 [NIST P-384]", "1.3.132.0.34", PD,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
                "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
                "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
                "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
                1, true);

        add("secp521r1 [NIST P-521]", "1.3.132.0.35", PD,
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
                "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
                "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
                "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
                1, true);

        /* ANSI X9.62 prime curves */
        add("X9.62 prime192v2", "1.2.840.10045.3.1.2", P,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
                "CC22D6DFB95C6B25E49C0D6364A4E5980C393AA21668D953",
                "EEA2BAE7E1497842F2DE7769CFE9C989C072AD696F48034A",
                "6574D11D69B6EC7A672BB82A083DF2F2B0847DE970B2DE15",
                "FFFFFFFFFFFFFFFFFFFFFFFE5FB1A724DC80418648D8DD31", 1, false);

        add("X9.62 prime192v3", "1.2.840.10045.3.1.3", P,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
                "22123DC2395A05CAA7423DAECCC94760A7D462256BD56916",
                "7D29778100C65A1DA1783716588DCE2B8B4AEE8E228F1896",
                "38A90F22637337334B49DCB66A6DC8F9978ACA7648A943B0",
                "FFFFFFFFFFFFFFFFFFFFFFFF7A62D031C83F4294F640EC13", 1, false);

        add("X9.62 prime239v1", "1.2.840.10045.3.1.4", P,
                "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF",
                "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC",
                "6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A",
                "0FFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF",
                "7DEBE8E4E90A5DAE6E4054CA530BA04654B36818CE226B39FCCB7B02F1AE",
                "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF9E5E9A9F5D9071FBD1522688909D0B", 1, false);

        add("X9.62 prime239v2", "1.2.840.10045.3.1.5", P,
                "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF",
                "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC",
                "617FAB6832576CBBFED50D99F0249C3FEE58B94BA0038C7AE84C8C832F2C",
                "38AF09D98727705120C921BB5E9E26296A3CDCF2F35757A0EAFD87B830E7",
                "5B0125E4DBEA0EC7206DA0FC01D9B081329FB555DE6EF460237DFF8BE4BA",
                "7FFFFFFFFFFFFFFFFFFFFFFF800000CFA7E8594377D414C03821BC582063", 1, false);

        add("X9.62 prime239v3", "1.2.840.10045.3.1.6", P,
                "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF",
                "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC",
                "255705FA2A306654B1F4CB03D6A750A30C250102D4988717D9BA15AB6D3E",
                "6768AE8E18BB92CFCF005C949AA2C6D94853D0E660BBF854B1C9505FE95A",
                "1607E6898F390C06BC1D552BAD226F3B6FCFE48B6E818499AF18E3ED6CF3",
                "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF975DEB41B3A6057C3C432146526551", 1, false);

        /**
         * Brainpool curves
         */

        add("brainpoolP160r1", "1.3.36.3.3.2.8.1.1.1", P,
                "E95E4A5F737059DC60DFC7AD95B3D8139515620F",
                "340E7BE2A280EB74E2BE61BADA745D97E8F7C300",
                "1E589A8595423412134FAA2DBDEC95C8D8675E58",
                "BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3",
                "1667CB477A1A8EC338F94741669C976316DA6321",
                "E95E4A5F737059DC60DF5991D45029409E60FC09", 1, false);

        add("brainpoolP192r1", "1.3.36.3.3.2.8.1.1.3", P,
                "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
                "6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF",
                "469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9",
                "C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6",
                "14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F",
                "C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1", 1, false);

        add("brainpoolP224r1", "1.3.36.3.3.2.8.1.1.5", P,
                "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
                "68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
                "2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
                "0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D",
                "58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD",
                "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F", 1, false);

        add("brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7", P,
                "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
                "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
                "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
                "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
                "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
                "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 1, false);

        add("brainpoolP320r1", "1.3.36.3.3.2.8.1.1.9", P,
                "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
                "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
                "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
                "43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",
                "14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
                "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311",
                1, false);

        add("brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11", P,
                "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
                "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
                "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
                "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
                "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
                "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
                1, false);

        add("brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13", P,
                "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
                "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
                "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
                "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
                "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
                "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
                1, false);
        SPLIT_PATTERN = null;
    }

    public String getName() {
        return curveName;
    }

    ECParameterSpec getECParameterSpec() {
        return this.ecps;
    }

    byte[] getEncoded() {
        return encoded.clone();
    }

}
