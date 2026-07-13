using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Extensions;

/// <summary>
/// One-shot notification banners rendered by the _Flash partial on the next page.
/// The standard way to give users feedback after any POST-redirect flow — new
/// features should use these instead of inventing their own messaging.
/// </summary>
public static class FlashExtensions
{
    public const string TypeKey = "FlashType";
    public const string MessageKey = "FlashMessage";

    public static void FlashSuccess(this Controller controller, string message)
        => Set(controller, "success", message);

    public static void FlashError(this Controller controller, string message)
        => Set(controller, "error", message);

    public static void FlashInfo(this Controller controller, string message)
        => Set(controller, "info", message);

    private static void Set(Controller controller, string type, string message)
    {
        controller.TempData[TypeKey] = type;
        controller.TempData[MessageKey] = message;
    }
}
