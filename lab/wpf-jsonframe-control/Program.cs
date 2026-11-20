using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

internal static class Program
{
    [STAThread]
    private static int Main()
    {
        _ = new Application();
        string path = Path.Combine(Path.GetTempPath(), $"h4-safe-page-{Guid.NewGuid():N}.xaml");
        File.WriteAllText(path,
            "<Page xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\"><TextBlock Text=\"INERT-PAGE\"/></Page>");
        try
        {
            string module = typeof(Frame).Assembly.Location;
            Console.WriteLine($"ProcessIdentity={System.Security.Principal.WindowsIdentity.GetCurrent().Name}");
            Console.WriteLine($"WpfModule={module}");
            Console.WriteLine($"WpfSha256={Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(module)))}");
            Console.WriteLine($"Runtime={Environment.Version}");

            Uri source = new(path);
            bool emptyLoaded = false;
            string emptyError = "none";
            try
            {
                Frame empty = JsonSerializer.Deserialize<Frame>("{}")!;
                emptyLoaded = PumpUntil(() => empty.Content is not null, TimeSpan.FromSeconds(2));
            }
            catch (Exception ex)
            {
                emptyError = ex.GetType().FullName ?? ex.GetType().Name;
            }

            bool directLoaded = false;
            string directError = "none";
            try
            {
                Frame direct = new() { Source = source };
                directLoaded = PumpUntil(() => direct.Content is not null, TimeSpan.FromSeconds(5));
            }
            catch (Exception ex)
            {
                directError = ex.GetType().FullName ?? ex.GetType().Name;
            }

            Frame? fromJson = null;
            string jsonError = "none";
            try
            {
                string json = JsonSerializer.Serialize(new { Source = source.AbsoluteUri });
                fromJson = JsonSerializer.Deserialize<Frame>(json);
            }
            catch (Exception ex)
            {
                jsonError = ex.GetType().FullName ?? ex.GetType().Name;
            }

            bool jsonLoaded = fromJson is not null
                && PumpUntil(() => fromJson.Content is not null, TimeSpan.FromSeconds(5));
            Console.WriteLine($"EmptyLoaded={emptyLoaded};EmptyError={emptyError};DirectLoaded={directLoaded};DirectError={directError};JsonConstructed={fromJson is not null};JsonSourceSet={fromJson?.Source is not null};JsonLoaded={jsonLoaded};JsonError={jsonError}");
            return 0;
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static bool PumpUntil(Func<bool> condition, TimeSpan timeout)
    {
        Stopwatch watch = Stopwatch.StartNew();
        while (!condition() && watch.Elapsed < timeout)
        {
            DispatcherFrame frame = new();
            DispatcherTimer timer = new(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromMilliseconds(50)
            };
            timer.Tick += (_, _) => { timer.Stop(); frame.Continue = false; };
            timer.Start();
            Dispatcher.PushFrame(frame);
        }

        return condition();
    }
}
