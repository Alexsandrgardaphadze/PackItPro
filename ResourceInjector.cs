using System;
using System.Collections.Generic;
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

            // Fix: Add requires ResourceId as key and List<Resource> as value
            var resourceId = new ResourceId((IntPtr)10);
            if (!ri.Resources.ContainsKey(resourceId))
            {
                ri.Resources.Add(resourceId, new List<Resource>());
            }
            ri.Resources[resourceId].Add(resource);

            ri.Save(outputPath);
        }
    }
}