using Microsoft.Msix.Utils;
using Microsoft.Msix.Utils.AppxPackaging;
using Microsoft.Msix.Utils.AppxPackagingInterop;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MsixVerifier
{
    internal class MsixInfo
    {
        private readonly bool isBundle;
        private IAppxBundleReader appxBundleReader;
        private IAppxPackageReader packageReader;
        private readonly byte[] P7xFileId = { 0x50, 0x4b, 0x43, 0x58 };
        private readonly int P7xFileIdSize;

        public MsixInfo(string msixPath)
        {
            P7xFileIdSize = P7xFileId.Length;

            var bundleStream = StreamUtils.CreateInputStreamOnFile(msixPath);            

            this.isBundle = FileExtensionHelper.HasUnencryptedBundleExtension(msixPath);
            if(this.isBundle)
            {
                IAppxBundleFactory bundleFactory = (IAppxBundleFactory)new AppxBundleFactory();
                this.appxBundleReader = bundleFactory.CreateBundleReader(bundleStream);
            }
            else
            {
                IAppxFactory packageFactory = (IAppxFactory)new AppxFactory();
                this.packageReader = packageFactory.CreatePackageReader(bundleStream);
            }
        }

        public byte[] GetSignature(bool skipP7xFileId)
        {
            var signatureFile = this.isBundle
                ? appxBundleReader.GetFootprintFile(APPX_BUNDLE_FOOTPRINT_FILE_TYPE.APPX_BUNDLE_FOOTPRINT_FILE_TYPE_SIGNATURE)
                :packageReader.GetFootprintFile(APPX_FOOTPRINT_FILE_TYPE.APPX_FOOTPRINT_FILE_TYPE_SIGNATURE);

            IntPtr pcbRead = IntPtr.Zero;
            

            var signatureStream = signatureFile.GetStream();
            var stat = StreamUtils.GetStreamSize(signatureStream);
            var highPart = (Int32)(stat >> 32);
            if (highPart != 0)
            {
                throw new Exception("Signature size should be small");
            }
            var signatureSize = (Int32)stat;
            if(signatureSize <= P7xFileIdSize)
            {
                throw new Exception();
            }
            if(skipP7xFileId)
            {
                // Validate msix signature header
                byte[] headerBuffer = new byte[P7xFileIdSize];
                signatureStream.Read(headerBuffer, P7xFileIdSize, pcbRead);
                signatureSize -= P7xFileIdSize;
            }
            byte[] signatureContent = new byte[signatureSize];

            IntPtr signatureRead = IntPtr.Zero;
            signatureStream.Read(signatureContent, signatureSize, signatureRead);

            return signatureContent;
        }
    }
}
