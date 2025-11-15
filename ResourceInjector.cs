using System;
using System.IO;
using Vestris.ResourceLib;

namespace PackItPro
{
    public static class ResourceInjector
    {
        public static void InjectPayload(string stubPath, string payloadZipPath, string outputPath)
        {
            File.Copy(stubPath, outputPath, overwrite: true);
            var payloadBytes = File.ReadAllBytes(payloadZipPath);

            using var ri = new ResourceInfo();
            ri.Load(outputPath);

            var resource = new GenericResource(
                new ResourceId("PAYLOAD"),
                new ResourceId((IntPtr)10), // RT_RCDATA
                0x0409
            );
            resource.Data = payloadBytes;

            ri.Resources.Add(resource);
            ri.Save(outputPath);
        }
    }
}