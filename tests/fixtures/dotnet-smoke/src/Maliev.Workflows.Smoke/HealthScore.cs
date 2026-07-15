namespace Maliev.Workflows.Smoke;

/// <summary>Provides a deterministic branch for reusable-workflow coverage validation.</summary>
public static class HealthScore
{
    /// <summary>Constrains a score to the inclusive range from zero to one hundred.</summary>
    public static int Clamp(int score) => Math.Clamp(score, 0, 100);
}
