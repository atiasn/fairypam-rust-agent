using System.IO;

namespace FairyPam.Agent;

internal sealed class SingleInstance(FileStream lockFile) : IDisposable
{
    public static bool TryAcquire(out SingleInstance? instance)
    {
        try
        {
            instance = new(WindowsProtectedPath.AcquireMachineLock());
            return true;
        }
        catch (Exception error) when (error is IOException
            or UnauthorizedAccessException
            or InvalidOperationException)
        {
            instance = null;
            return false;
        }
    }

    public void Dispose() => lockFile.Dispose();
}
