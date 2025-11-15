// ResourceInjector.cs
using System;
using System.IO;
using Vestris.ResourceLib; // Requires installing the NuGet package

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
                new ResourceId("PAYLOAD"), // Resource Name
                new ResourceId((IntPtr)10), // RT_RCDATA (integer ID 10)
                0x0409 // Language ID (0x0409 = English US)
            );
            resource.Data = payloadBytes;

            // Ensure the resource collection for RT_RCDATA exists
            var rcDataId = new ResourceId((IntPtr)10);
            if (!ri.Resources.ContainsKey(rcDataId))
            {
                ri.Resources.Add(rcDataId, new System.Collections.Generic.List<Resource>());
            }
            ri.Resources[rcDataId].Add(resource);

            ri.Save(outputPath);
        }
    }
}