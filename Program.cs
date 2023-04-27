using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

namespace MsixVerifier
{
    internal class Program
    {
        static void Main(string[] args)
        {

            //var msixPath = @"TestSignedApp.msix";
            var msixPath = @"d:\tmp\source1.msix";
            bool isvaild = ValidateTrustInfo(msixPath, false);
        }

        private static unsafe bool ValidateTrustInfo(string msixPath, bool verifyMicrosoftOrigin)
        {
            bool result = false;
            try
            {
                bool verifyChainResult = false;

                // First verify certificate chain if requested.
                if (verifyMicrosoftOrigin)
                {
                    var certificate = GetCertContextFromMsix(msixPath);

                    // Get certificate chain context for validation
                    X509Chain chain = new X509Chain();
                    chain.Build(certificate);

                    // Validate that the certificate chain is rooted in one of the well-known Microsoft root certs
                    CERT_CHAIN_POLICY_PARA policyParameters = new CERT_CHAIN_POLICY_PARA(0);
                    policyParameters.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
                    policyParameters.dwFlags = 0x00020000; // MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG
                    IntPtr policyOid = (IntPtr)7; // CERT_CHAIN_POLICY_MICROSOFT_ROOT
                    CERT_CHAIN_POLICY_STATUS policyStatus = new CERT_CHAIN_POLICY_STATUS(0);

                    var certChainVerifySucceeded = Crypt32.CertVerifyCertificateChainPolicy(
                        policyOid,
                        chain.ChainContext,
                        ref policyParameters,
                        ref policyStatus);
                    verifyChainResult = certChainVerifySucceeded && policyStatus.dwError == 0;
                }
                else
                {
                    verifyChainResult = true;
                }
                // If certificate chain origin validation is success or not requested, then validate the trust info of the file.
                if (verifyChainResult)
                {
                    var pathPtr = Marshal.StringToHGlobalUni(msixPath);
                    try
                    {
                        var flags = WinTrustProviderFlags.NONE;
                        var revocationFlags = WinTrustRevocationChecks.WTD_REVOKE_NONE;
                        flags |= WinTrustProviderFlags.WTD_CACHE_ONLY_URL_RETRIEVAL;
                        flags |= WinTrustProviderFlags.WTD_REVOCATION_CHECK_CHAIN;
                        revocationFlags |= WinTrustRevocationChecks.WTD_REVOKE_WHOLECHAIN;

                        var trust = stackalloc WINTRUST_DATA[1];
                        var fileInfo = stackalloc WINTRUST_FILE_INFO[1];
                        trust->cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>();
                        trust->dwProvFlags = flags;
                        trust->dwStateAction = WinTrustStateAction.WTD_STATEACTION_IGNORE;
                        trust->dwUIChoice = WinTrustDataUIChoice.WTD_UI_NONE;
                        trust->dwUIContext = WinTrustUIContext.WTD_UICONTEXT_EXECUTE;
                        trust->dwUnionChoice = WinTrustUnionChoice.WTD_CHOICE_FILE;
                        trust->fdwRevocationChecks = revocationFlags;
                        trust->trustUnion = new WINTRUST_DATA_UNION
                        {
                            pFile = fileInfo
                        };
                        trust->trustUnion.pFile->cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>();
                        trust->trustUnion.pFile->pcwszFilePath = pathPtr;
                        var verifyTrustResult = Wintrust.WinVerifyTrustEx(new IntPtr(-1), KnownGuids.WINTRUST_ACTION_GENERIC_VERIFY_V2, trust);
                        var signatureCheckResult = (SignatureCheckResult)verifyTrustResult;

                        result = signatureCheckResult == SignatureCheckResult.Valid;
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pathPtr);
                    }
                }
            }
            catch (Exception ex)
            {
                result = false;
            }
            return result;
        }

        private static unsafe X509Certificate2? GetCertContextFromMsix(string msixPath)
        {
            var msixInfo = new MsixInfo(msixPath);
            var signatureContent = msixInfo.GetSignature(true);

            fixed (byte* pin = signatureContent)
            {
                var blob = new CRYPTOAPI_BLOB
                {
                    cbData = (uint)signatureContent.Length,
                    pbData = new IntPtr(pin)
                };
                var result = Crypt32.CryptQueryObject(
                        CryptQueryObjectType.CERT_QUERY_OBJECT_BLOB,
                        ref blob,
                        CryptQueryContentFlagType.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                        CryptQueryFormatFlagType.CERT_QUERY_FORMAT_FLAG_BINARY,
                        CryptQueryObjectFlags.NONE,
                        out _,
                        out _,
                        out _,
                        out var phCertStore,
                        out var msgHandle,
                        IntPtr.Zero);
                if (!result)
                {
                    msgHandle.Dispose();
                    throw new InvalidOperationException("Unable to read signature.");
                }
                var contentSize = 0u;
                byte[]? Content;
                if (Crypt32.CryptMsgGetParam(msgHandle, CryptMsgParamType.CMSG_CONTENT_PARAM, 0, LocalBufferSafeHandle.Zero, ref contentSize))
                {
                    using var contentHandle = LocalBufferSafeHandle.Alloc(contentSize);
                    if (Crypt32.CryptMsgGetParam(msgHandle, CryptMsgParamType.CMSG_CONTENT_PARAM, 0, contentHandle, ref contentSize))
                    {
                        Content = new byte[contentSize];
                        Marshal.Copy(contentHandle.DangerousGetHandle(), Content, 0, (int)contentSize);
                    }
                }
                var signerSize = 0u;
                if (!Crypt32.CryptMsgGetParam(msgHandle, CryptMsgParamType.CMSG_SIGNER_INFO_PARAM, 0, LocalBufferSafeHandle.Zero, ref signerSize))
                {
                    throw new InvalidOperationException();
                }
                using var signerHandle = LocalBufferSafeHandle.Alloc(signerSize);
                if (!Crypt32.CryptMsgGetParam(msgHandle, CryptMsgParamType.CMSG_SIGNER_INFO_PARAM, 0, signerHandle, ref signerSize))
                {
                    throw new InvalidOperationException();
                }
                var signerInfo = Marshal.PtrToStructure<CMSG_SIGNER_INFO>(signerHandle.DangerousGetHandle());
                var subjectId = new UniversalSubjectIdentifier(signerInfo.Issuer, signerInfo.SerialNumber);
                var certs = GetCertificatesFromMessage(msgHandle);
                var certificate = FindCertificate((X509IssuerSerial)subjectId.Value, certs);
                return certificate;
            }
        }

        private static protected X509Certificate2Collection GetCertificatesFromMessage(CryptMsgSafeHandle handle)
        {
            var size = (uint)Marshal.SizeOf<uint>();
            var certs = new X509Certificate2Collection();
            uint certCount;
            using (var certCountLocalBuffer = LocalBufferSafeHandle.Alloc(size))
            {
                if (!Crypt32.CryptMsgGetParam(handle, CryptMsgParamType.CMSG_CERT_COUNT_PARAM, 0, certCountLocalBuffer, ref size))
                {
                    return certs;
                }
                certCount = unchecked((uint)Marshal.ReadInt32(certCountLocalBuffer.DangerousGetHandle(), 0));
            }
            if (certCount == 0)
            {
                return certs;
            }
            for (var i = 0u; i < certCount; i++)
            {
                uint certSize = 0;
                if (!Crypt32.CryptMsgGetParam(handle, CryptMsgParamType.CMSG_CERT_PARAM, i, LocalBufferSafeHandle.Zero, ref certSize))
                {
                    continue;
                }

                using var certLocalBuffer = LocalBufferSafeHandle.Alloc(certSize);
                if (!Crypt32.CryptMsgGetParam(handle, CryptMsgParamType.CMSG_CERT_PARAM, i, certLocalBuffer, ref certSize))
                {
                    continue;
                }
                var data = new byte[certSize];
                Marshal.Copy(certLocalBuffer.DangerousGetHandle(), data, 0, data.Length);
                var cert = new X509Certificate2(data);
                certs.Add(cert);
            }
            return certs;
        }

        private static protected X509Certificate2? FindCertificate(X509IssuerSerial issuerSerial, X509Certificate2Collection certificateCollection)
        {
            var byDN = certificateCollection.Find(X509FindType.FindByIssuerDistinguishedName, issuerSerial.IssuerName, false);
            if (byDN.Count < 1)
            {
                return null;
            }
            var bySerial = byDN.Find(X509FindType.FindBySerialNumber, issuerSerial.SerialNumber, false);
            if (bySerial.Count != 1)
            {
                return null;
            }
            return bySerial[0];
        }
    }
}