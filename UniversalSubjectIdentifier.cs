namespace MsixVerifier
{
    using System.Runtime.InteropServices;
    using System.Security.Cryptography.Pkcs;
    using System.Security.Cryptography.Xml;
    using System.Text;

    internal class UniversalSubjectIdentifier
    {
        public SubjectIdentifierType Type { get; }
        public object Value { get; }

        public UniversalSubjectIdentifier(CRYPTOAPI_BLOB issuer, CRYPTOAPI_BLOB serialNumber)
        {
            var allZeroSerial = IsBlobAllZero(serialNumber);
            if (allZeroSerial)
            {
                var flags = EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING;
                uint size = 0;
                if (Crypt32.CryptDecodeObjectEx(flags, (IntPtr)7, issuer.pbData, issuer.cbData, CryptDecodeFlags.CRYPT_DECODE_ALLOC_FLAG, IntPtr.Zero, out var x500Name, ref size))
                {
                    using (x500Name)
                    {
                        var info = Marshal.PtrToStructure<CERT_NAME_INFO>(x500Name.DangerousGetHandle());
                        for (var i = 0L; i < info.cRDN; i++)
                        {
                            var rdn = Marshal.PtrToStructure<CERT_RDN>(new IntPtr(info.rgRDN.ToInt64() + i * Marshal.SizeOf<CERT_RDN>()));
                            for (var j = 0; j < rdn.cRDNAttr; j++)
                            {
                                var attribute = Marshal.PtrToStructure<CERT_RDN_ATTR>(new IntPtr(rdn.rgRDNAttr.ToInt64() + j * Marshal.SizeOf<CERT_RDN_ATTR>()));
                                if (attribute.pszObjId == KnownOids.KeyId)
                                {
                                    Type = SubjectIdentifierType.SubjectKeyIdentifier;
                                    var ski = attribute.Value.AsSpan();
                                    Value = HexHelpers.HexEncodeBigEndian(ski);
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            unsafe
            {
                var result = Crypt32.CertNameToStr(EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING, new IntPtr(&issuer), CertNameStrType.CERT_X500_NAME_STR | CertNameStrType.CERT_NAME_STR_REVERSE_FLAG, null, 0);
                if (result <= 1)
                {
                    throw new InvalidOperationException();
                }
                var builder = new StringBuilder((int)result);
                var final = Crypt32.CertNameToStr(EncodingType.PKCS_7_ASN_ENCODING | EncodingType.X509_ASN_ENCODING, new IntPtr(&issuer), CertNameStrType.CERT_X500_NAME_STR | CertNameStrType.CERT_NAME_STR_REVERSE_FLAG, builder, result);
                if (final <= 1)
                {
                    throw new InvalidOperationException();
                }
                var serial = serialNumber.AsSpan();
                var issuerSerial = new X509IssuerSerial
                {
                    IssuerName = builder.ToString(),
                    SerialNumber = HexHelpers.HexEncodeBigEndian(serial)
                };
                Value = issuerSerial;
                Type = SubjectIdentifierType.IssuerAndSerialNumber;
            }
        }

        private static bool IsBlobAllZero(CRYPTOAPI_BLOB blob)
        {
            var data = blob.AsSpan();
            for (var i = 0; i < data.Length; i++)
            {
                if (data[i] != 0)
                {
                    return false;
                }
            }
            return true;

        }
    }
}